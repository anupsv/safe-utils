/**
 * Security dashboard page
 * Main entry point for security monitoring interface
 */

import SecurityDashboard from '@/components/security/SecurityDashboard';
import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Security Dashboard - Safe Utils',
  description: 'Real-time security monitoring and threat analysis dashboard',
  robots: {
    index: false,
    follow: false
  }
};

export default function SecurityPage(): JSX.Element {
  return (
    <main>
      <SecurityDashboard />
    </main>
  );
}