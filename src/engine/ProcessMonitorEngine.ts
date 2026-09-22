/**
 * Process Monitoring Engine
 * Detects hidden processes, rootkits, and suspicious behavior
 * Uses native Android APIs for real process enumeration
 */

import {IEngine, EngineStatus} from './interfaces/IEngine';
import {ProcessInfo, Threat, ThreatType, ThreatLevel} from '../types';
import {calculateRiskScore} from '../utils/helpers';
import {SENSITIVITY_LEVELS} from '../utils/constants';
import {store} from '../store';
import {setProcesses, updateProcess} from '../store/slices/processesSlice';
import {addThreat} from '../store/slices/threatsSlice';
import {v4 as uuidv4} from 'uuid';

class ProcessMonitorEngine implements IEngine {
  private running: boolean = false;
  private scanInterval: NodeJS.Timeout | null = null;
  private lastScanTime: number = 0;
  private threatsDetected: number = 0;
  private errors: string[] = [];
  private baselineProcesses: Set<number> = new Set();

  async initialize(): Promise<void> {
    // Initialize native module connection
    // This will be implemented with React Native bridge to native Android code
    console.log('ProcessMonitorEngine: Initializing...');
  }

  async start(): Promise<void> {
    if (this.running) {
      console.warn('ProcessMonitorEngine: Already running');
      return;
    }

    this.running = true;
    console.log('ProcessMonitorEngine: Starting...');

    // Establish baseline on first run
    await this.establishBaseline();

    // Start periodic scanning
    this.scanInterval = setInterval(() => {
      this.scanProcesses().catch(error => {
        console.error('ProcessMonitorEngine: Scan error:', error);
        this.errors.push(error.message);
      });
    }, 5000); // Scan every 5 seconds

    // Initial scan
    await this.scanProcesses();
  }

  async stop(): Promise<void> {
    if (!this.running) return;

    this.running = false;
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }

    console.log('ProcessMonitorEngine: Stopped');
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
   * Establish baseline of known safe processes
   */
  private async establishBaseline(): Promise<void> {
    try {
      const processes = await this.enumerateProcesses();
      this.baselineProcesses = new Set(processes.map(p => p.pid));
      console.log(`ProcessMonitorEngine: Baseline established with ${processes.length} processes`);
    } catch (error) {
      console.error('ProcessMonitorEngine: Failed to establish baseline:', error);
    }
  }

  /**
   * Enumerate all running processes
   * This will call native Android code via React Native bridge
   */
  private async enumerateProcesses(): Promise<ProcessInfo[]> {
    // TODO: Implement native bridge to Android ActivityManager
    // For now, return empty array - will be implemented with native module
    try {
      // Native call: ProcessMonitorNativeModule.getRunningProcesses()
      // This is a placeholder - actual implementation will use React Native bridge
      return [];
    } catch (error) {
      console.error('ProcessMonitorEngine: Failed to enumerate processes:', error);
      throw error;
    }
  }

  /**
   * Scan processes for threats
   */
  private async scanProcesses(): Promise<void> {
    try {
      const processes = await this.enumerateProcesses();
      const suspiciousProcesses: ProcessInfo[] = [];
      const currentPids = new Set(processes.map(p => p.pid));

      // Detect hidden processes (in baseline but not in current scan)
      const hiddenPids = new Set(
        Array.from(this.baselineProcesses).filter(pid => !currentPids.has(pid)),
      );

      for (const process of processes) {
        // Calculate risk score
        const riskScore = calculateRiskScore({
          cpuUsage: process.cpuUsage,
          memoryUsage: process.memoryUsage,
          isHidden: process.isHidden,
          suspiciousIndicators: process.suspiciousIndicators,
          networkActivity: false, // Will be determined by network monitor
        });

        process.riskScore = riskScore;

        // Check for suspicious indicators
        const indicators: string[] = [];

        // High CPU usage without UI
        if (process.cpuUsage > 50 && !process.packageName) {
          indicators.push('High CPU usage without UI');
        }

        // Hidden process
        if (process.isHidden) {
          indicators.push('Hidden process detected');
        }

        // Unusual parent-child relationship
        if (process.parentPid && process.parentPid !== 1) {
          const parentProcess = processes.find(p => p.pid === process.parentPid);
          if (!parentProcess || parentProcess.name !== 'zygote') {
            indicators.push('Unusual parent-child relationship');
          }
        }

        // High memory allocation
        if (process.memoryUsage > 512) {
          indicators.push('Excessive memory allocation');
        }

        process.suspiciousIndicators = indicators;

        // Update Redux store
        store.dispatch(updateProcess(process));

        // Check if process is suspicious based on sensitivity level
        const sensitivity = store.getState().settings.sensitivityLevel;
        const threshold = SENSITIVITY_LEVELS[sensitivity].RISK_THRESHOLD;

        if (riskScore > threshold || indicators.length > 0) {
          suspiciousProcesses.push(process);
        }
      }

      // Detect rootkit (hidden processes)
      if (hiddenPids.size > 0) {
        await this.detectRootkit(Array.from(hiddenPids));
      }

      // Create threats for suspicious processes
      for (const process of suspiciousProcesses) {
        await this.createThreatFromProcess(process);
      }

      // Update process list in store
      store.dispatch(setProcesses(processes));

      this.lastScanTime = Date.now();
    } catch (error) {
      console.error('ProcessMonitorEngine: Scan error:', error);
      this.errors.push(error.message);
    }
  }

  /**
   * Detect rootkit based on hidden processes
   */
  private async detectRootkit(hiddenPids: number[]): Promise<void> {
    const threat: Threat = {
      id: uuidv4(),
      type: ThreatType.ROOTKIT,
      level: ThreatLevel.CRITICAL,
      timestamp: Date.now(),
      detectedBy: 'ProcessMonitorEngine',
      title: 'Rootkit Detected',
      description: `Hidden processes detected: ${hiddenPids.length} processes disappeared from process list`,
      technicalDetails: `Process IDs: ${hiddenPids.join(', ')}. This indicates possible rootkit activity where processes are hidden from normal enumeration.`,
      userFriendlyExplanation:
        'A rootkit was detected on your device. This is a hidden program that can give attackers full control of your device. This is very dangerous and requires immediate attention.',
      blocked: false,
      actions: [
        {
          type: 'ALERTED',
          timestamp: Date.now(),
          description: 'User alerted about rootkit detection',
        },
      ],
      metadata: {
        processIds: hiddenPids,
      },
    };

    store.dispatch(addThreat(threat));
    this.threatsDetected++;
  }

  /**
   * Create threat from suspicious process
   */
  private async createThreatFromProcess(process: ProcessInfo): Promise<void> {
    const threat: Threat = {
      id: uuidv4(),
      type: ThreatType.SUSPICIOUS_PROCESS,
      level:
        process.riskScore > 80
          ? ThreatLevel.CRITICAL
          : process.riskScore > 50
          ? ThreatLevel.HIGH
          : ThreatLevel.MEDIUM,
      timestamp: Date.now(),
      detectedBy: 'ProcessMonitorEngine',
      title: `Suspicious Process: ${process.name}`,
      description: `Process ${process.name} (PID: ${process.pid}) shows suspicious behavior`,
      technicalDetails: `PID: ${process.pid}, CPU: ${process.cpuUsage}%, Memory: ${process.memoryUsage}MB, Risk Score: ${process.riskScore}, Indicators: ${process.suspiciousIndicators.join(', ')}`,
      userFriendlyExplanation: `A suspicious program called "${process.name}" is running on your device. It might be trying to access your personal information or damage your device.`,
      blocked: false,
      actions: [
        {
          type: 'ALERTED',
          timestamp: Date.now(),
          description: 'User alerted about suspicious process',
        },
      ],
      metadata: {
        processName: process.name,
        processId: process.pid,
        riskScore: process.riskScore,
        suspiciousIndicators: process.suspiciousIndicators,
      },
    };

    store.dispatch(addThreat(threat));
    this.threatsDetected++;
  }
}

export default new ProcessMonitorEngine();
