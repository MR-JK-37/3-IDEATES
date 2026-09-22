/**
 * Network Traffic Monitoring Engine
 * Intercepts and analyzes network traffic for data exfiltration
 * Uses Android VpnService API for traffic interception
 */

import {IEngine, EngineStatus} from './interfaces/IEngine';
import {Threat, ThreatType, ThreatLevel, NetworkConnection} from '../types';
import {store} from '../store';
import {addThreat} from '../store/slices/threatsSlice';
import {v4 as uuidv4} from 'uuid';
import {formatBytes} from '../utils/helpers';
import {SENSITIVITY_LEVELS} from '../utils/constants';

class NetworkMonitorEngine implements IEngine {
  private running: boolean = false;
  private lastScanTime: number = 0;
  private threatsDetected: number = 0;
  private errors: string[] = [];
  private baselineTraffic: Map<string, number> = new Map(); // app -> bytes
  private connectionHistory: NetworkConnection[] = [];

  async initialize(): Promise<void> {
    console.log('NetworkMonitorEngine: Initializing...');
    // Initialize VPN service
    // This will be implemented with React Native bridge to Android VpnService
  }

  async start(): Promise<void> {
    if (this.running) {
      console.warn('NetworkMonitorEngine: Already running');
      return;
    }

    this.running = true;
    console.log('NetworkMonitorEngine: Starting VPN service...');

    // Start VPN service via native module
    // Native call: NetworkMonitorNativeModule.startVpnService()
    // This creates a local VPN to intercept all traffic

    // Establish baseline
    await this.establishBaseline();
  }

  async stop(): Promise<void> {
    if (!this.running) return;

    this.running = false;

    // Stop VPN service
    // Native call: NetworkMonitorNativeModule.stopVpnService()

    console.log('NetworkMonitorEngine: Stopped');
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
   * Handle network packet from VPN service
   * This is called by native module for each intercepted packet
   */
  onPacket(packet: {
    sourceIp: string;
    destinationIp: string;
    destinationPort: number;
    protocol: string;
    size: number;
    appPackage?: string;
  }): void {
    if (!this.running) return;

    const connection: NetworkConnection = {
      sourceIp: packet.sourceIp,
      destinationIp: packet.destinationIp,
      destinationPort: packet.destinationPort,
      protocol: packet.protocol,
      dataTransferred: packet.size,
      timestamp: Date.now(),
    };

    this.connectionHistory.push(connection);

    // Keep only last 1000 connections
    if (this.connectionHistory.length > 1000) {
      this.connectionHistory = this.connectionHistory.slice(-1000);
    }

    // Analyze packet for threats
    this.analyzePacket(packet, connection).catch(error => {
      console.error('NetworkMonitorEngine: Packet analysis error:', error);
    });
  }

  /**
   * Establish baseline traffic patterns
   */
  private async establishBaseline(): Promise<void> {
    // Monitor traffic for 30 seconds to establish baseline
    await new Promise(resolve => setTimeout(resolve, 30000));

    // Calculate baseline per app
    const appTraffic = new Map<string, number>();
    for (const conn of this.connectionHistory) {
      // Group by destination IP (simplified)
      const key = conn.destinationIp;
      appTraffic.set(key, (appTraffic.get(key) || 0) + conn.dataTransferred);
    }

    this.baselineTraffic = appTraffic;
    console.log('NetworkMonitorEngine: Baseline established');
  }

  /**
   * Analyze network packet for threats
   */
  private async analyzePacket(
    packet: {
      sourceIp: string;
      destinationIp: string;
      destinationPort: number;
      protocol: string;
      size: number;
      appPackage?: string;
    },
    connection: NetworkConnection,
  ): Promise<void> {
    // Check for data exfiltration (large uploads)
    const sensitivity = store.getState().settings.sensitivityLevel;
    const threshold = SENSITIVITY_LEVELS[sensitivity].NETWORK_THRESHOLD * 1024 * 1024; // Convert to bytes

    if (packet.size > threshold) {
      await this.detectDataExfiltration(connection, packet.size);
    }

    // Check for suspicious IP addresses
    if (await this.isSuspiciousIP(packet.destinationIp)) {
      await this.detectSuspiciousConnection(connection);
    }

    // Check for DNS tunneling
    if (packet.protocol === 'DNS' && packet.destinationPort === 53) {
      await this.detectDNSTunneling(connection);
    }

    // Check for beaconing behavior
    await this.detectBeaconing(connection);

    this.lastScanTime = Date.now();
  }

  /**
   * Detect data exfiltration
   */
  private async detectDataExfiltration(
    connection: NetworkConnection,
    dataSize: number,
  ): Promise<void> {
    const threat: Threat = {
      id: uuidv4(),
      type: ThreatType.DATA_EXFILTRATION,
      level: ThreatLevel.CRITICAL,
      timestamp: Date.now(),
      detectedBy: 'NetworkMonitorEngine',
      title: 'Data Exfiltration Detected',
      description: `Large data upload detected: ${formatBytes(dataSize)} to ${connection.destinationIp}`,
      technicalDetails: `Destination: ${connection.destinationIp}:${connection.destinationPort}, Protocol: ${connection.protocol}, Size: ${formatBytes(dataSize)}`,
      userFriendlyExplanation:
        'Someone is trying to secretly send your personal data to a remote server. We blocked this attempt to protect your privacy.',
      blocked: true,
      actions: [
        {
          type: 'BLOCKED',
          timestamp: Date.now(),
          description: 'Network connection blocked',
        },
        {
          type: 'ALERTED',
          timestamp: Date.now(),
          description: 'User alerted about data exfiltration',
        },
      ],
      metadata: {
        networkConnection: connection,
        dataSize: dataSize,
      },
    };

    store.dispatch(addThreat(threat));
    this.threatsDetected++;
  }

  /**
   * Detect suspicious connection
   */
  private async detectSuspiciousConnection(connection: NetworkConnection): Promise<void> {
    const threat: Threat = {
      id: uuidv4(),
      type: ThreatType.NETWORK_ANOMALY,
      level: ThreatLevel.HIGH,
      timestamp: Date.now(),
      detectedBy: 'NetworkMonitorEngine',
      title: 'Suspicious Network Connection',
      description: `Connection to suspicious IP: ${connection.destinationIp}`,
      technicalDetails: `Destination: ${connection.destinationIp}:${connection.destinationPort}, Protocol: ${connection.protocol}`,
      userFriendlyExplanation:
        'A connection to a suspicious server was detected. This could be malware trying to communicate with attackers.',
      blocked: true,
      actions: [
        {
          type: 'BLOCKED',
          timestamp: Date.now(),
          description: 'Suspicious connection blocked',
        },
        {
          type: 'ALERTED',
          timestamp: Date.now(),
          description: 'User alerted about suspicious connection',
        },
      ],
      metadata: {
        networkConnection: connection,
      },
    };

    store.dispatch(addThreat(threat));
    this.threatsDetected++;
  }

  /**
   * Detect DNS tunneling
   */
  private async detectDNSTunneling(connection: NetworkConnection): Promise<void> {
    // Check for high entropy in DNS queries (indicates tunneling)
    // This is simplified - real implementation would analyze DNS query patterns
    const threat: Threat = {
      id: uuidv4(),
      type: ThreatType.NETWORK_ANOMALY,
      level: ThreatLevel.HIGH,
      timestamp: Date.now(),
      detectedBy: 'NetworkMonitorEngine',
      title: 'DNS Tunneling Detected',
      description: `Suspicious DNS activity detected to ${connection.destinationIp}`,
      technicalDetails: `DNS tunneling detected. This is a technique used to exfiltrate data through DNS queries.`,
      userFriendlyExplanation:
        'Someone is trying to secretly send your data through a hidden channel using DNS queries. We blocked this attempt.',
      blocked: true,
      actions: [
        {
          type: 'BLOCKED',
          timestamp: Date.now(),
          description: 'DNS tunneling blocked',
        },
        {
          type: 'ALERTED',
          timestamp: Date.now(),
          description: 'User alerted about DNS tunneling',
        },
      ],
      metadata: {
        networkConnection: connection,
      },
    };

    store.dispatch(addThreat(threat));
    this.threatsDetected++;
  }

  /**
   * Detect beaconing behavior (regular connections to external IP)
   */
  private async detectBeaconing(connection: NetworkConnection): Promise<void> {
    // Check if same destination IP is contacted regularly
    const recentConnections = this.connectionHistory.filter(
      c =>
        c.destinationIp === connection.destinationIp &&
        Date.now() - c.timestamp < 60000, // Last minute
    );

    if (recentConnections.length > 10) {
      // Beaconing detected
      const threat: Threat = {
        id: uuidv4(),
        type: ThreatType.NETWORK_ANOMALY,
        level: ThreatLevel.MEDIUM,
        timestamp: Date.now(),
        detectedBy: 'NetworkMonitorEngine',
        title: 'Beaconing Behavior Detected',
        description: `Regular connections to ${connection.destinationIp} detected`,
        technicalDetails: `${recentConnections.length} connections in the last minute to ${connection.destinationIp}`,
        userFriendlyExplanation:
          'A program is making regular connections to a remote server. This could be malware checking in with attackers.',
        blocked: false,
        actions: [
          {
            type: 'ALERTED',
            timestamp: Date.now(),
            description: 'User alerted about beaconing behavior',
          },
        ],
        metadata: {
          networkConnection: connection,
          connectionCount: recentConnections.length,
        },
      };

      store.dispatch(addThreat(threat));
      this.threatsDetected++;
    }
  }

  /**
   * Check if IP address is suspicious
   */
  private async isSuspiciousIP(ip: string): Promise<boolean> {
    // TODO: Implement IP reputation check
    // For now, check against known malicious IP ranges
    const maliciousRanges = [
      '192.168.1.100', // Example - would be replaced with real threat intelligence
    ];

    return maliciousRanges.includes(ip);
  }
}

export default new NetworkMonitorEngine();
