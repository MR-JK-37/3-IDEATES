/**
 * Utility helper functions
 */

import {ThreatLevel, ThreatType} from '../types';
import {format, formatDistanceToNow} from 'date-fns';

/**
 * Format timestamp to readable date
 */
export const formatDate = (timestamp: number): string => {
  return format(new Date(timestamp), 'MMM dd, yyyy HH:mm:ss');
};

/**
 * Format timestamp to relative time
 */
export const formatRelativeTime = (timestamp: number): string => {
  return formatDistanceToNow(new Date(timestamp), {addSuffix: true});
};

/**
 * Format bytes to human readable size
 */
export const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
};

/**
 * Get threat level color
 */
export const getThreatLevelColor = (level: ThreatLevel): string => {
  const colors = {
    [ThreatLevel.LOW]: '#00F5FF',
    [ThreatLevel.MEDIUM]: '#FFB800',
    [ThreatLevel.HIGH]: '#FF6B35',
    [ThreatLevel.CRITICAL]: '#FF006E',
  };
  return colors[level];
};

/**
 * Get threat type icon
 */
export const getThreatTypeIcon = (type: ThreatType): string => {
  const icons = {
    [ThreatType.MALWARE]: '🦠',
    [ThreatType.PHISHING]: '🎣',
    [ThreatType.ROOTKIT]: '🔓',
    [ThreatType.DATA_EXFILTRATION]: '📤',
    [ThreatType.CRYPTO_MINING]: '⛏️',
    [ThreatType.SUSPICIOUS_PROCESS]: '⚙️',
    [ThreatType.NETWORK_ANOMALY]: '🌐',
    [ThreatType.FILE_MODIFICATION]: '📁',
  };
  return icons[type] || '⚠️';
};

/**
 * Calculate risk score from multiple factors
 */
export const calculateRiskScore = (factors: {
  cpuUsage?: number;
  memoryUsage?: number;
  isHidden?: boolean;
  suspiciousIndicators?: string[];
  networkActivity?: boolean;
}): number => {
  let score = 0;

  // CPU usage (0-30 points)
  if (factors.cpuUsage) {
    score += Math.min(factors.cpuUsage / 3, 30);
  }

  // Memory usage (0-20 points)
  if (factors.memoryUsage) {
    score += Math.min(factors.memoryUsage / 25, 20);
  }

  // Hidden process (20 points)
  if (factors.isHidden) {
    score += 20;
  }

  // Suspicious indicators (10 points each, max 30)
  if (factors.suspiciousIndicators) {
    score += Math.min(factors.suspiciousIndicators.length * 10, 30);
  }

  // Network activity (0-20 points)
  if (factors.networkActivity) {
    score += 20;
  }

  return Math.min(Math.round(score), 100);
};

/**
 * Generate user-friendly threat explanation
 */
export const generateThreatExplanation = (
  type: ThreatType,
  technicalDetails: string,
): string => {
  const explanations: Record<ThreatType, string> = {
    [ThreatType.MALWARE]:
      'A malicious program was detected on your device. This could steal your personal information, damage your files, or take control of your device.',
    [ThreatType.PHISHING]:
      'A fake website was detected trying to steal your login credentials. Never enter your password on suspicious websites.',
    [ThreatType.ROOTKIT]:
      'A hidden program was found that could give attackers full control of your device. This is very dangerous.',
    [ThreatType.DATA_EXFILTRATION]:
      'Someone is trying to secretly send your personal data to a remote server. We blocked this attempt.',
    [ThreatType.CRYPTO_MINING]:
      'A program is using your device to mine cryptocurrency without your permission. This drains your battery and slows down your device.',
    [ThreatType.SUSPICIOUS_PROCESS]:
      'A suspicious program is running in the background. It might be trying to access your personal information.',
    [ThreatType.NETWORK_ANOMALY]:
      'Unusual network activity was detected. This could indicate someone is trying to access your device remotely.',
    [ThreatType.FILE_MODIFICATION]:
      'A program is trying to modify important system files. This could damage your device or install malware.',
  };

  return explanations[type] || 'A security threat was detected on your device.';
};

/**
 * Validate URL format
 */
export const isValidUrl = (url: string): boolean => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

/**
 * Extract domain from URL
 */
export const extractDomain = (url: string): string | null => {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch {
    return null;
  }
};

/**
 * Check if domain is suspicious
 */
export const isSuspiciousDomain = (domain: string): boolean => {
  const suspiciousPatterns = [
    /bit\.ly/i,
    /tinyurl\.com/i,
    /t\.co/i,
    /goo\.gl/i,
    /short\.link/i,
    /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // IP address
  ];

  return suspiciousPatterns.some(pattern => pattern.test(domain));
};

/**
 * Debounce function
 */
export const debounce = <T extends (...args: any[]) => any>(
  func: T,
  wait: number,
): ((...args: Parameters<T>) => void) => {
  let timeout: NodeJS.Timeout | null = null;

  return (...args: Parameters<T>) => {
    if (timeout) clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
};

/**
 * Throttle function
 */
export const throttle = <T extends (...args: any[]) => any>(
  func: T,
  limit: number,
): ((...args: Parameters<T>) => void) => {
  let inThrottle: boolean;

  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
};
