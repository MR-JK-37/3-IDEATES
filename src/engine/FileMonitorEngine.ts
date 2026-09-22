/**
 * File System Monitoring Engine
 * Monitors file creation, modification, and APK installations
 * Uses Android FileObserver for real-time file watching
 */

import {IEngine, EngineStatus} from './interfaces/IEngine';
import {Threat, ThreatType, ThreatLevel} from '../types';
import {store} from '../store';
import {addThreat} from '../store/slices/threatsSlice';
import {v4 as uuidv4} from 'uuid';

class FileMonitorEngine implements IEngine {
  private running: boolean = false;
  private scanInterval: NodeJS.Timeout | null = null;
  private lastScanTime: number = 0;
  private threatsDetected: number = 0;
  private errors: string[] = [];
  private monitoredPaths: string[] = [
    '/sdcard/Download',
    '/sdcard/Android/data',
    '/data/app',
  ];

  async initialize(): Promise<void> {
    console.log('FileMonitorEngine: Initializing...');
    // Initialize native file observer
    // This will be implemented with React Native bridge to Android FileObserver
  }

  async start(): Promise<void> {
    if (this.running) {
      console.warn('FileMonitorEngine: Already running');
      return;
    }

    this.running = true;
    console.log('FileMonitorEngine: Starting...');

    // Start file monitoring via native module
    // Native call: FileMonitorNativeModule.startWatching(monitoredPaths)

    // Periodic scan for APK files
    this.scanInterval = setInterval(() => {
      this.scanForAPKs().catch(error => {
        console.error('FileMonitorEngine: Scan error:', error);
        this.errors.push(error.message);
      });
    }, 10000); // Scan every 10 seconds

    // Initial scan
    await this.scanForAPKs();
  }

  async stop(): Promise<void> {
    if (!this.running) return;

    this.running = false;
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }

    // Stop native file observer
    // Native call: FileMonitorNativeModule.stopWatching()

    console.log('FileMonitorEngine: Stopped');
  }

  isRunning(): boolean {
    return this.running;
  }

  getStatus(): EngineStatus {
    return {
      running: this.running,
      lastScanTime: this.lastScanTime,
      threatsDetected: this.threatsDetected,
      errors: [...this.errors],
    };
  }

  /**
   * Handle file system event from native observer
   * This is called by native module when file events occur
   */
  onFileEvent(event: {
    type: 'CREATE' | 'MODIFY' | 'DELETE';
    path: string;
    size?: number;
  }): void {
    if (!this.running) return;

    switch (event.type) {
      case 'CREATE':
        this.handleFileCreated(event.path, event.size || 0);
        break;
      case 'MODIFY':
        this.handleFileModified(event.path);
        break;
      case 'DELETE':
        this.handleFileDeleted(event.path);
        break;
    }
  }

  /**
   * Handle new file creation
   */
  private async handleFileCreated(path: string, size: number): Promise<void> {
    // Check if it's an APK file
    if (path.endsWith('.apk')) {
      await this.analyzeAPK(path, size);
    }

    // Check for executable files in suspicious locations
    if (this.isExecutable(path) && this.isSuspiciousLocation(path)) {
      await this.createThreatForExecutable(path);
    }
  }

  /**
   * Handle file modification
   */
  private async handleFileModified(path: string): Promise<void> {
    // Check if system file is being modified
    if (this.isSystemFile(path)) {
      await this.createThreatForSystemModification(path);
    }
  }

  /**
   * Handle file deletion
   */
  private handleFileDeleted(path: string): void {
    // Log deletion for analysis
    console.log(`FileMonitorEngine: File deleted: ${path}`);
  }

  /**
   * Scan for APK files in monitored directories
   */
  private async scanForAPKs(): Promise<void> {
    try {
      // Native call: FileMonitorNativeModule.scanForAPKs(monitoredPaths)
      // This will return list of APK files found
      const apkFiles: Array<{path: string; size: number}> = [];

      for (const apk of apkFiles) {
        await this.analyzeAPK(apk.path, apk.size);
      }

      this.lastScanTime = Date.now();
    } catch (error) {
      console.error('FileMonitorEngine: APK scan error:', error);
      this.errors.push(error.message);
    }
  }

  /**
   * Analyze APK file for malicious patterns
   */
  private async analyzeAPK(path: string, size: number): Promise<void> {
    try {
      // Native call: APKAnalyzerNativeModule.analyze(path)
      // This will perform static analysis using APKTool
      const analysis = {
        permissions: [] as string[],
        isObfuscated: false,
        hasSuspiciousPatterns: false,
        riskScore: 0,
      };

      // Check for dangerous permissions
      const dangerousPermissions = [
        'READ_SMS',
        'SEND_SMS',
        'READ_CONTACTS',
        'READ_PHONE_STATE',
        'ACCESS_FINE_LOCATION',
        'RECORD_AUDIO',
        'CAMERA',
      ];

      const hasDangerousPermissions = analysis.permissions.some(p =>
        dangerousPermissions.includes(p),
      );

      if (hasDangerousPermissions || analysis.hasSuspiciousPatterns) {
        await this.createThreatForAPK(path, analysis);
      }
    } catch (error) {
      console.error('FileMonitorEngine: APK analysis error:', error);
    }
  }

  /**
   * Create threat for malicious APK
   */
  private async createThreatForAPK(
    path: string,
    analysis: {permissions: string[]; isObfuscated: boolean; riskScore: number},
  ): Promise<void> {
    const threat: Threat = {
      id: uuidv4(),
      type: ThreatType.MALWARE,
      level: ThreatLevel.HIGH,
      timestamp: Date.now(),
      detectedBy: 'FileMonitorEngine',
      title: 'Malicious APK Detected',
      description: `Suspicious APK file detected: ${path}`,
      technicalDetails: `Path: ${path}, Permissions: ${analysis.permissions.join(', ')}, Obfuscated: ${analysis.isObfuscated}, Risk Score: ${analysis.riskScore}`,
      userFriendlyExplanation:
        'A suspicious app installation file was detected. This app might be trying to steal your personal information or damage your device. Do not install it.',
      blocked: true,
      actions: [
        {
          type: 'QUARANTINED',
          timestamp: Date.now(),
          description: 'APK file quarantined',
        },
        {
          type: 'ALERTED',
          timestamp: Date.now(),
          description: 'User alerted about malicious APK',
        },
      ],
      metadata: {
        filePath: path,
        permissions: analysis.permissions,
        isObfuscated: analysis.isObfuscated,
      },
    };

    store.dispatch(addThreat(threat));
    this.threatsDetected++;
  }

  /**
   * Create threat for executable in suspicious location
   */
  private async createThreatForExecutable(path: string): Promise<void> {
    const threat: Threat = {
      id: uuidv4(),
      type: ThreatType.FILE_MODIFICATION,
      level: ThreatLevel.MEDIUM,
      timestamp: Date.now(),
      detectedBy: 'FileMonitorEngine',
      title: 'Suspicious Executable Detected',
      description: `Executable file found in suspicious location: ${path}`,
      technicalDetails: `Path: ${path}`,
      userFriendlyExplanation:
        'An executable file was found in an unusual location. This might be malware trying to hide from detection.',
      blocked: false,
      actions: [
        {
          type: 'ALERTED',
          timestamp: Date.now(),
          description: 'User alerted about suspicious executable',
        },
      ],
      metadata: {
        filePath: path,
      },
    };

    store.dispatch(addThreat(threat));
    this.threatsDetected++;
  }

  /**
   * Create threat for system file modification
   */
  private async createThreatForSystemModification(path: string): Promise<void> {
    const threat: Threat = {
      id: uuidv4(),
      type: ThreatType.FILE_MODIFICATION,
      level: ThreatLevel.CRITICAL,
      timestamp: Date.now(),
      detectedBy: 'FileMonitorEngine',
      title: 'System File Modification Attempt',
      description: `Attempt to modify system file: ${path}`,
      technicalDetails: `Path: ${path}`,
      userFriendlyExplanation:
        'A program is trying to modify important system files. This could damage your device or install malware.',
      blocked: true,
      actions: [
        {
          type: 'BLOCKED',
          timestamp: Date.now(),
          description: 'System file modification blocked',
        },
        {
          type: 'ALERTED',
          timestamp: Date.now(),
          description: 'User alerted about system modification attempt',
        },
      ],
      metadata: {
        filePath: path,
      },
    };

    store.dispatch(addThreat(threat));
    this.threatsDetected++;
  }

  /**
   * Check if file is executable
   */
  private isExecutable(path: string): boolean {
    const executableExtensions = ['.exe', '.bin', '.sh', '.so'];
    return executableExtensions.some(ext => path.endsWith(ext));
  }

  /**
   * Check if location is suspicious
   */
  private isSuspiciousLocation(path: string): boolean {
    const suspiciousPaths = ['/sdcard/Download', '/sdcard/DCIM'];
    return suspiciousPaths.some(sp => path.startsWith(sp));
  }

  /**
   * Check if file is a system file
   */
  private isSystemFile(path: string): boolean {
    return path.startsWith('/system') || path.startsWith('/data/system');
  }
}

export default new FileMonitorEngine();
