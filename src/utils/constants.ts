/**
 * Application constants
 */

export const COLORS = {
  // Primary colors
  PRIMARY: '#00F5FF',
  SECONDARY: '#FF006E',
  ACCENT: '#00F5FF',
  
  // Background colors (dark theme)
  BACKGROUND: '#0A0E27',
  SURFACE: '#151932',
  SURFACE_ELEVATED: '#1E2447',
  
  // Text colors
  TEXT_PRIMARY: '#FFFFFF',
  TEXT_SECONDARY: '#B0B8D1',
  TEXT_DISABLED: '#6B7280',
  
  // Threat level colors
  THREAT_CRITICAL: '#FF006E',
  THREAT_HIGH: '#FF6B35',
  THREAT_MEDIUM: '#FFB800',
  THREAT_LOW: '#00F5FF',
  
  // Status colors
  SUCCESS: '#00FF88',
  WARNING: '#FFB800',
  ERROR: '#FF006E',
  INFO: '#00F5FF',
  
  // Glassmorphism
  GLASS_BACKGROUND: 'rgba(255, 255, 255, 0.05)',
  GLASS_BORDER: 'rgba(255, 255, 255, 0.1)',
};

export const SPACING = {
  XS: 4,
  SM: 8,
  MD: 16,
  LG: 24,
  XL: 32,
  XXL: 48,
};

export const TYPOGRAPHY = {
  FONT_SIZE: {
    XS: 12,
    SM: 14,
    MD: 16,
    LG: 18,
    XL: 24,
    XXL: 32,
    XXXL: 48,
  },
  FONT_WEIGHT: {
    REGULAR: '400' as const,
    MEDIUM: '500' as const,
    SEMI_BOLD: '600' as const,
    BOLD: '700' as const,
  },
};

export const ANIMATION = {
  DURATION: {
    FAST: 150,
    NORMAL: 300,
    SLOW: 500,
  },
  EASING: {
    EASE_IN: 'ease-in',
    EASE_OUT: 'ease-out',
    EASE_IN_OUT: 'ease-in-out',
  },
};

export const MONITORING = {
  PROCESS_SCAN_INTERVAL: 5000, // 5 seconds
  FILE_SCAN_INTERVAL: 10000, // 10 seconds
  NETWORK_SCAN_INTERVAL: 1000, // 1 second
  THREAT_ALERT_DELAY: 1000, // 1 second
};

export const SENSITIVITY_LEVELS = {
  LOW: {
    RISK_THRESHOLD: 80,
    CPU_THRESHOLD: 50,
    MEMORY_THRESHOLD: 512, // MB
    NETWORK_THRESHOLD: 100, // MB
  },
  MEDIUM: {
    RISK_THRESHOLD: 50,
    CPU_THRESHOLD: 30,
    MEMORY_THRESHOLD: 256, // MB
    NETWORK_THRESHOLD: 50, // MB
  },
  HIGH: {
    RISK_THRESHOLD: 30,
    CPU_THRESHOLD: 20,
    MEMORY_THRESHOLD: 128, // MB
    NETWORK_THRESHOLD: 25, // MB
  },
};

export const SUSPICIOUS_PATTERNS = {
  PROCESS: [
    'High CPU usage without UI',
    'Hidden process',
    'Unusual parent-child relationship',
    'Process name obfuscation',
    'Root access request',
  ],
  FILE: [
    'APK installation outside Play Store',
    'System partition modification',
    'Executable in download folder',
    'Obfuscated code detected',
    'Dangerous permissions requested',
  ],
  NETWORK: [
    'Large data upload',
    'DNS tunneling detected',
    'Connection to suspicious IP',
    'Beaconing behavior',
    'Unusual port usage',
  ],
};
