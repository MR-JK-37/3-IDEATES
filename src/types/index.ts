/**
 * Core type definitions for CyberDefense Mobile Application
 */

export enum ThreatLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export enum ThreatType {
  MALWARE = 'MALWARE',
  PHISHING = 'PHISHING',
  ROOTKIT = 'ROOTKIT',
  DATA_EXFILTRATION = 'DATA_EXFILTRATION',
  CRYPTO_MINING = 'CRYPTO_MINING',
  SUSPICIOUS_PROCESS = 'SUSPICIOUS_PROCESS',
  NETWORK_ANOMALY = 'NETWORK_ANOMALY',
  FILE_MODIFICATION = 'FILE_MODIFICATION',
}

export enum ProtectionStatus {
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  SCANNING = 'SCANNING',
  ERROR = 'ERROR',
}

export interface Threat {
  id: string;
  type: ThreatType;
  level: ThreatLevel;
  timestamp: number;
  detectedBy: string; // Engine that detected it
  title: string;
  description: string;
  technicalDetails: string;
  userFriendlyExplanation: string;
  blocked: boolean;
  actions: ThreatAction[];
  metadata: ThreatMetadata;
}

export interface ThreatAction {
  type: 'BLOCKED' | 'QUARANTINED' | 'ALERTED' | 'LOGGED';
  timestamp: number;
  description: string;
}

export interface ThreatMetadata {
  processName?: string;
  processId?: number;
  filePath?: string;
  networkConnection?: NetworkConnection;
  url?: string;
  domain?: string;
  ipAddress?: string;
  port?: number;
  dataSize?: number;
  behavior?: MalwareBehavior;
  [key: string]: any;
}

export interface NetworkConnection {
  sourceIp: string;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  dataTransferred: number;
  timestamp: number;
}

export interface MalwareBehavior {
  filesModified: string[];
  filesCreated: string[];
  filesDeleted: string[];
  networkConnections: NetworkConnection[];
  permissionsRequested: string[];
  suspiciousPatterns: string[];
  systemCalls: string[];
  cpuUsage: number;
  memoryUsage: number;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  packageName?: string;
  cpuUsage: number;
  memoryUsage: number;
  parentPid?: number;
  isHidden: boolean;
  riskScore: number;
  suspiciousIndicators: string[];
}

export interface SystemHealth {
  protectionStatus: ProtectionStatus;
  activeThreats: number;
  threatsBlockedToday: number;
  lastScanTime: number;
  cpuUsage: number;
  memoryUsage: number;
  batteryImpact: number;
  engineStatus: EngineStatus;
}

export interface EngineStatus {
  processMonitor: boolean;
  fileMonitor: boolean;
  networkMonitor: boolean;
  phishingDetector: boolean;
  malwareSandbox: boolean;
  llmExplainer: boolean;
}

export interface AppSettings {
  processMonitoring: boolean;
  fileMonitoring: boolean;
  networkMonitoring: boolean;
  phishingDetection: boolean;
  malwareSandbox: boolean;
  sensitivityLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  notificationsEnabled: boolean;
  hapticFeedback: boolean;
  darkMode: boolean;
  excludedPackages: string[];
  excludedPaths: string[];
}

export interface PhishingAssessment {
  isPhishing: boolean;
  confidence: number;
  reasons: string[];
  url: string;
  domain: string;
  visualSimilarity?: number;
  certificateValid?: boolean;
}

export interface SandboxResult {
  threatName: string;
  threatLevel: ThreatLevel;
  behavior: MalwareBehavior;
  recommendation: string;
  analysisDuration: number;
  timestamp: number;
}
