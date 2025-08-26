import { fetchSecure4ByteSignature } from './secure-4byte';
import { SecureValidator, SecureLogger } from '@/lib/security';
import { processError } from '@/lib/secure-error-handler';
import { sanitizeHtml, sanitizeAddress } from '@/lib/secure-output';

export async function decodeTransactionData(to: string, data: string, chainId: string): Promise<any> {
  const validator = SecureValidator.getInstance();
  
  try {
    // Input validation and sanitization
    const cleanTo = validator.validateEthereumAddress(to);
    const cleanData = validator.validateHexData(data);
    const cleanChainId = validator.sanitizeString(chainId, 20);
    
    if (cleanData === "0x" || !cleanData) {
      return {
        method: "0x (ETH Transfer)",
        parameters: []
      };
    }
    
    // Validate minimum data length for method ID
    if (cleanData.length < 10) {
      return {
        method: "Invalid",
        error: "Data too short for method ID",
        parameters: []
      };
    }
    
    const methodId = cleanData.slice(0, 10);
    const rawData = cleanData.slice(10);
    
    // Secure signature lookup with comprehensive protection
    const signature = await fetchSecure4ByteSignature(methodId);
    
    if (!signature) {
      return {
        method: "Unknown",
        methodId: sanitizeHtml(methodId),
        parameters: [{
          name: "data",
          type: "bytes",
          value: sanitizeHtml(cleanData)
        }]
      };
    }
    
    // Parse method signature safely
    const methodName = signature.split('(')[0];
    const paramTypesString = signature.split('(')[1]?.replace(')', '') || '';
    const paramTypes = paramTypesString ? paramTypesString.split(',') : [];
    
    let params: { name: string; type: string; value: string }[] = [];
    
    if (rawData && paramTypes.length > 0) {
      try {
        let dataPosition = 0;
        
        for (let i = 0; i < paramTypes.length && i < 20; i++) { // Limit parameters to prevent DoS
          const type = paramTypes[i].trim();
          let value = "";
          
          // Validate we have enough data remaining
          if (dataPosition >= rawData.length) {
            break;
          }
          
          if (type === "address") {
            if (dataPosition + 64 > rawData.length) break;
            const hex = rawData.slice(dataPosition, dataPosition + 64);
            const addressValue = "0x" + hex.slice(24);
            
            // Validate extracted address
            try {
              value = sanitizeAddress(addressValue);
            } catch (error) {
              value = sanitizeHtml(addressValue);
            }
            dataPosition += 64;
          } 
          else if (type.startsWith("uint") || type.startsWith("int")) {
            if (dataPosition + 64 > rawData.length) break;
            const hex = rawData.slice(dataPosition, dataPosition + 64);
            
            try {
              // Validate hex before BigInt conversion
              const hexValue = "0x" + hex;
              if (!/^0x[a-fA-F0-9]+$/.test(hexValue)) {
                value = sanitizeHtml(hexValue);
              } else {
                const bigIntValue = BigInt(hexValue);
                // Limit very large numbers for display
                if (bigIntValue > BigInt("0xffffffffffffffffffffffffffffffff")) {
                  value = "Large number (truncated)";
                } else {
                  value = bigIntValue.toString();
                }
              }
            } catch (error) {
              value = sanitizeHtml("0x" + hex);
            }
            dataPosition += 64;
          } 
          else if (type === "bool") {
            if (dataPosition + 64 > rawData.length) break;
            const hex = rawData.slice(dataPosition, dataPosition + 64);
            
            try {
              const boolValue = BigInt("0x" + hex).toString() === "0" ? "false" : "true";
              value = boolValue;
            } catch (error) {
              value = sanitizeHtml("0x" + hex);
            }
            dataPosition += 64;
          } 
          else if (type === "bytes" || type.startsWith("bytes")) {
            const remainingData = rawData.slice(dataPosition);
            // Limit bytes data to prevent DoS
            const truncatedData = remainingData.length > 1000 ? 
              remainingData.slice(0, 1000) + "..." : remainingData;
            value = sanitizeHtml("0x" + truncatedData);
            break;
          } 
          else {
            // Unknown type - take remaining data with limits
            const remainingData = rawData.slice(dataPosition);
            const truncatedData = remainingData.length > 200 ? 
              remainingData.slice(0, 200) + "..." : remainingData;
            value = sanitizeHtml("0x" + truncatedData);
            break;
          }
          
          params.push({
            name: sanitizeHtml(`param${i}`),
            type: sanitizeHtml(type),
            value: value
          });
        }
      } catch (error) {
        SecureLogger.error("Error parsing transaction parameters", error as Error);
        params = [{
          name: "encodedData",
          type: "bytes",
          value: sanitizeHtml("0x" + rawData.slice(0, 200)) // Limit for security
        }];
      }
    }
    
    // If no parameters were parsed but we have raw data, include it securely
    if (params.length === 0 && rawData) {
      params = [{
        name: "encodedData",
        type: "bytes",
        value: sanitizeHtml("0x" + rawData.slice(0, 200)) // Limit for security
      }];
    }
    
    const result = {
      method: sanitizeHtml(methodName),
      signature: sanitizeHtml(signature),
      parameters: params
    };
    
    SecureLogger.info(`Transaction data decoded successfully for method: ${methodName}`);
    return result;
    
  } catch (error) {
    const secureError = processError(error, {
      to: to.substring(0, 10) + '...', // Partial address for logging
      dataLength: data.length,
      context: 'transaction_data_decoding'
    });
    
    SecureLogger.error("Transaction data decoding failed", error as Error);
    
    return {
      method: "Error decoding",
      error: sanitizeHtml(secureError.userMessage),
      parameters: []
    };
  }
}