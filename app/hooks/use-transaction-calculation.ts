import { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { ReadonlyURLSearchParams } from "next/navigation";
import { useToast } from "@/hooks/use-toast";
import { NETWORKS } from "@/app/constants";
import { UltraSecureHashCalculator } from "@/lib/secure-hash-calculator";
import { fetchSecureTransactionDataFromApi } from "@/utils/secure-api";
import { FormData, CalculationResult, TransactionParams } from "@/types/form-types";
import { decodeTransactionData } from "@/utils/decoding/transactionData";
import { encodeExecTransaction } from "@/utils/encoding/execTransaction";
import { SecureValidator, SecureLogger, processError } from "@/lib/security";
import { sanitizeHtml, sanitizeAddress } from "@/lib/secure-output";
import { cryptoIntegrity } from "@/lib/crypto-integrity";

export function useTransactionCalculation(searchParams: ReadonlyURLSearchParams) {
  const [result, setResult] = useState<CalculationResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [step, setStep] = useState(1);
  const [calculationRequested, setCalculationRequested] = useState(false);

  const { toast } = useToast();

  // Extract parameters from URL with comprehensive security validation
  const validator = SecureValidator.getInstance();
  
  const [safeAddress] = useState(() => {
    try {
      const rawAddress = searchParams.get("safeAddress") || "";
      return sanitizeHtml(rawAddress);
    } catch (error) {
      SecureLogger.error('Failed to extract safe address from URL', error as Error);
      return "";
    }
  });
  
  const [network] = useState(() => {
    try {
      const prefix = safeAddress.split(":")[0];
      const foundNetwork = NETWORKS.find((n) => n.gnosisPrefix === prefix);
      return foundNetwork ? validator.validateNetworkName(foundNetwork.value) : "";
    } catch (error) {
      SecureLogger.error('Failed to extract network from URL', error as Error);
      return "";
    }
  });

  const [chainId] = useState(() => {
    try {
      const prefix = safeAddress.split(":")[0];
      const foundNetwork = NETWORKS.find((n) => n.gnosisPrefix === prefix);
      return foundNetwork?.chainId.toString() || "";
    } catch (error) {
      SecureLogger.error('Failed to extract chain ID from URL', error as Error);
      return "";
    }
  });

  const [address] = useState(() => {
    try {
      const _address = safeAddress.match(/0x[a-fA-F0-9]{40}/)?.[0];
      if (_address) {
        return sanitizeAddress(_address);
      } else {
        return "";
      }
    } catch (error) {
      SecureLogger.error('Failed to extract address from URL', error as Error);
      return "";
    }
  });

  const [nonce] = useState(() => {
    try {
      const rawNonce = searchParams.get("nonce") || "";
      return rawNonce ? validator.validateNonce(rawNonce).toString() : "";
    } catch (error) {
      SecureLogger.error('Failed to extract nonce from URL', error as Error);
      return "";
    }
  });

  // Initialize form
  const form = useForm<FormData>({
    defaultValues: {
      method: "direct",
      network: network,
      chainId: Number(chainId),
      address: address,
      nonce: nonce,
      to: "0x0000000000000000000000000000000000000000",
      value: "0",
      data: "0x",
      operation: "0",
      safeTxGas: "0",
      baseGas: "0",
      gasPrice: "0",
      gasToken: "0x0000000000000000000000000000000000000000",
      refundReceiver: "0x0000000000000000000000000000000000000000",
      version: "1.3.0"
    },
  });

  // Set initial values from search parameter
  useEffect(() => {
    if (safeAddress) {
      form.setValue("network", network);
      form.setValue("chainId", Number(chainId));
      form.setValue("address", address);
      if (nonce) {
        form.setValue("nonce", nonce);
        form.setValue("method", "api");
      }
    }
  }, [safeAddress, nonce, form, network, chainId, address]);

  // Verify form validity to proceed to next step
  const validateStep = (currentStep: number) => {
    if (currentStep === 1) {
      // Verify Basic Info data
      const { network, chainId, address, nonce, version } = form.getValues();
      return !!network && !!chainId && !!address && !!nonce && !!version;
    }
    if (currentStep === 2) {
      // Verify Transaction data
      const { to, operation } = form.getValues();
      return !!to && !!operation;
    }
    return true;
  };

  // Function to go to next step
  const nextStep = () => {
    if (validateStep(step)) {
      setStep(step + 1);
      return true;
    } else {
      toast({
        title: "Missing required fields",
        description: "Please fill in all required fields to continue.",
        variant: "destructive",
      });
      return false;
    }
  };

  const prevStep = () => {
    setStep(Math.max(1, step - 1));
  };

  const handleSubmit = async (data: FormData) => {
    setIsLoading(true);
    setResult(null);
    setCalculationRequested(true);
  
    try {
      // Input validation with security controls
      const validatedData = {
        network: validator.validateNetworkName(data.network),
        address: validator.validateEthereumAddress(data.address),
        nonce: validator.validateNonce(data.nonce).toString(),
        chainId: data.chainId,
        to: validator.validateEthereumAddress(data.to),
        value: validator.sanitizeString(data.value),
        data: validator.validateHexData(data.data),
        operation: validator.sanitizeString(data.operation),
        safeTxGas: validator.sanitizeString(data.safeTxGas),
        baseGas: validator.sanitizeString(data.baseGas),
        gasPrice: validator.sanitizeString(data.gasPrice),
        gasToken: validator.validateEthereumAddress(data.gasToken),
        refundReceiver: validator.validateEthereumAddress(data.refundReceiver),
        version: validator.sanitizeString(data.version),
        method: data.method
      };
      
      let txParams: TransactionParams = {
        to: validatedData.to,
        value: validatedData.value,
        data: validatedData.data,
        operation: validatedData.operation,
        safeTxGas: validatedData.safeTxGas,
        baseGas: validatedData.baseGas,
        gasPrice: validatedData.gasPrice,
        gasToken: validatedData.gasToken,
        refundReceiver: validatedData.refundReceiver,
        nonce: validatedData.nonce,
        version: validatedData.version,
        dataDecoded: null
      };
      
      if (validatedData.method === "api") {
        try {
          txParams = await fetchSecureTransactionDataFromApi(
            validatedData.network,
            validatedData.address,
            validatedData.nonce
          );
        } catch (error: any) {
          setCalculationRequested(false);
          const secureError = processError(error, { method: 'api', network: validatedData.network });
          throw new Error(secureError.userMessage);
        }
      }

      if (!txParams.dataDecoded && txParams.data !== "0x") {
        txParams.dataDecoded = await decodeTransactionData(
          txParams.to, 
          txParams.data, 
          data.chainId.toString()
        );
      }

      const execTransactionCall = encodeExecTransaction(
        txParams.to,
        txParams.value,
        txParams.data,
        txParams.operation.toString(),
        txParams.safeTxGas.toString(),
        txParams.baseGas,
        txParams.gasPrice,
        txParams.gasToken,
        txParams.refundReceiver,
        txParams.signatures || "0x"
      );
      
      // Use secure hash calculator with integrity verification
      const calculator = UltraSecureHashCalculator.getInstance();
      
      const hashResult = await calculator.calculateHashes(
        validatedData.chainId.toString(),
        validatedData.address,
        txParams.to,
        txParams.value,
        txParams.data,
        txParams.operation.toString(),
        txParams.safeTxGas,
        txParams.baseGas,
        txParams.gasPrice,
        txParams.gasToken,
        txParams.refundReceiver,
        txParams.nonce,
        txParams.version
      );
      
      const { domainHash, messageHash, safeTxHash, encodedMessage } = hashResult;
      
      // Verify cryptographic integrity
      if (!cryptoIntegrity.verifyDomainHash(
        validatedData.chainId.toString(),
        validatedData.address,
        txParams.version,
        domainHash
      )) {
        throw new Error('Domain hash integrity verification failed');
      }
      
      if (!cryptoIntegrity.verifyTransactionHash(
        txParams.version,
        { to: txParams.to, value: txParams.value, data: txParams.data },
        safeTxHash
      )) {
        throw new Error('Transaction hash integrity verification failed');
      }

      let nestedSafe = null;
      if (data.nestedSafeEnabled && data.nestedSafeAddress && data.nestedSafeNonce) {
        try {
          // Validate nested Safe parameters
          const nestedSafeAddress = validator.validateEthereumAddress(data.nestedSafeAddress);
          const nestedSafeNonce = validator.validateNonce(data.nestedSafeNonce).toString();
          const nestedSafeVersion = validator.sanitizeString(data.nestedSafeVersion || txParams.version);

          const nestedSafeResult = await calculator.calculateNestedSafeApprovalHash(
            validatedData.chainId.toString(),
            validatedData.address,
            nestedSafeAddress,
            nestedSafeNonce,
            safeTxHash,
            nestedSafeVersion
          );
          
          // Verify nested Safe hash integrity
          if (!cryptoIntegrity.verifyTransactionHash(
            nestedSafeVersion,
            { to: validatedData.address, operation: '0' },
            nestedSafeResult.safeTxHash
          )) {
            throw new Error('Nested Safe hash integrity verification failed');
          }

          nestedSafe = {
            safeTxHash: nestedSafeResult.safeTxHash,
            domainHash: nestedSafeResult.domainHash,
            messageHash: nestedSafeResult.messageHash,
            encodedMessage: nestedSafeResult.encodedMessage,
            nestedSafeAddress: nestedSafeAddress,
            nestedSafeNonce: nestedSafeNonce,
            nestedSafeVersion: nestedSafeVersion
          };
        } catch (error) {
          const secureError = processError(error, { context: 'nested_safe_calculation' });
          SecureLogger.error('Nested Safe calculation failed', error as Error);
          throw new Error(secureError.userMessage);
        }
      }

      // Sanitize all output data before setting result
      setResult({
        network: {
          name: sanitizeHtml(NETWORKS.find(n => n.value === validatedData.network)?.label || validatedData.network),
          chain_id: sanitizeHtml(validatedData.chainId.toString()),
        },
        transaction: {
          multisig_address: sanitizeAddress(validatedData.address),
          to: sanitizeAddress(txParams.to),
          nonce: sanitizeHtml(txParams.nonce),
          version: sanitizeHtml(txParams.version),
          value: sanitizeHtml(txParams.value),
          data: sanitizeHtml(txParams.data),
          encoded_message: sanitizeHtml(encodedMessage),
          data_decoded: txParams.dataDecoded || {
            method: sanitizeHtml(txParams.data === "0x" ? "0x (ETH Transfer)" : "Unknown"),
            parameters: []
          },
          exec_transaction: {
            encoded: sanitizeHtml(execTransactionCall.encoded),
            decoded: execTransactionCall.decoded
          },
          signatures: txParams.signatures !== "0x" ? sanitizeHtml(txParams.signatures) : undefined
        },
        hashes: {
          domain_hash: sanitizeHtml(domainHash),
          message_hash: sanitizeHtml(messageHash),
          safe_transaction_hash: sanitizeHtml(safeTxHash),
        },
        nestedSafe: nestedSafe
      });
      
      SecureLogger.info('Hash calculation completed successfully');

    } catch (error: any) {
      const secureError = processError(error, {
        method: data.method,
        network: data.network,
        address: data.address?.substring(0, 10) + '...', // Partial address for logging
        context: 'transaction_calculation'
      });
      
      SecureLogger.error('Transaction calculation failed', error as Error);
      
      if (data.method === "api" && secureError.category === 'NETWORK') {
        setCalculationRequested(false);
      } else {
        setResult({
          error: sanitizeHtml(secureError.userMessage)
        });
      }
      
      toast({
        title: "Error",
        description: secureError.userMessage,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return {
    form,
    result,
    isLoading,
    calculationRequested,
    handleSubmit: form.handleSubmit(handleSubmit),
    safeAddress,
    network,
    chainId,
    address,
    nonce,
    step,
    nextStep,
    prevStep,
    validateStep
  };
}