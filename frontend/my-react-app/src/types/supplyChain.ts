export type ScannerState = "pass" | "warn" | "fail" | "unknown";

export type SupplyChainStatus = {
  id: string;
  image?: string | null;
  namespace?: string | null;
  podName?: string | null;
  cosignStatus?: ScannerState;
  trivyStatus?: ScannerState;
  criticalCves?: number | null;
  highCves?: number | null;
  signatureIssuer?: string | null;
  lastScannedAt?: string | null;
};
