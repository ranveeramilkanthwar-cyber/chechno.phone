/**
 * PrivaIndia DPDP Act 2023 Shared Types & Interfaces
 * Used across Next.js Web Portal and Expo React Native Mobile Companion.
 */

export type BrokerCategory =
  | 'DSA_LOAN_CREDIT'
  | 'B2B_LOCAL_DIRECTORY'
  | 'CALLER_ID_PEOPLE'
  | 'CLASSIFIEDS_PROPERTY'
  | 'PUBLIC_GAZETTE_GOVT';

export type ExposureStatus =
  | 'CLEAR'
  | 'EXPOSED'
  | 'PENDING'
  | 'REMOVED'
  | 'NOT_REMOVABLE';

export type OptOutChannel =
  | 'REST_WEBHOOK'
  | 'PLAYWRIGHT_FORM'
  | 'DPO_EMAIL'
  | 'EXEMPT';

export interface BrokerExposure {
  id: string;
  name: string;
  domain: string;
  category: BrokerCategory | string;
  exposed: string[];
  removable: boolean;
  selected: boolean;
  status: ExposureStatus;
  channel: OptOutChannel | string;
  dpoEmail?: string;
  lastUpdated?: string;
}

export interface DPDPUserIdentity {
  phone: string;
  name: string;
  email: string;
  circle: string;
  consentGranted: boolean;
  consentArtefactId: string;
  ed25519Signature: string;
}

export interface SyncEventPayload {
  event_type:
    | 'SCAN_PROGRESS'
    | 'CONSENT_TOGGLED'
    | 'REMOVAL_DISPATCHED'
    | 'STATUS_VERIFIED'
    | 'HEALER_PATCHED'
    | 'THEME_CHANGED';
  scan_id: string;
  broker_id?: string;
  status?: ExposureStatus;
  selected?: boolean;
  progress_step?: number;
  timestamp: string;
  payload?: any;
}
