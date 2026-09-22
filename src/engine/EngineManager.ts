/**
 * Engine Manager
 * Coordinates all security engines
 */

import ProcessMonitorEngine from './ProcessMonitorEngine';
import FileMonitorEngine from './FileMonitorEngine';
import NetworkMonitorEngine from './NetworkMonitorEngine';
import PhishingDetectorEngine from './PhishingDetectorEngine';
import {IEngine} from './interfaces/IEngine';
import {store} from '../store';
import {setEngineStatus} from '../store/slices/systemHealthSlice';
import {ProtectionStatus} from '../types';

class EngineManager {
  private engines: Map<string, IEngine> = new Map();
  private initialized: boolean = false;

  constructor() {
    // Register all engines
    this.engines.set('processMonitor', ProcessMonitorEngine);
    this.engines.set('fileMonitor', FileMonitorEngine);
    this.engines.set('networkMonitor', NetworkMonitorEngine);
    this.engines.set('phishingDetector', PhishingDetectorEngine);
  }

  /**
   * Initialize all engines
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      console.warn('EngineManager: Already initialized');
      return;
    }

    console.log('EngineManager: Initializing all engines...');

    const initPromises = Array.from(this.engines.entries()).map(async ([name, engine]) => {
      try {
        await engine.initialize();
        console.log(`EngineManager: ${name} initialized`);
      } catch (error) {
        console.error(`EngineManager: Failed to initialize ${name}:`, error);
      }
    });

    await Promise.all(initPromises);
    this.initialized = true;
  }

  /**
   * Start all enabled engines
   */
  async start(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }

    const settings = store.getState().settings;
    store.dispatch(
      setEngineStatus({
        processMonitor: false,
        fileMonitor: false,
        networkMonitor: false,
        phishingDetector: false,
        malwareSandbox: false,
        llmExplainer: false,
      }),
    );

    console.log('EngineManager: Starting engines...');

    // Start Process Monitor
    if (settings.processMonitoring) {
      try {
        await ProcessMonitorEngine.start();
        store.dispatch(setEngineStatus({processMonitor: true}));
      } catch (error) {
        console.error('EngineManager: Failed to start ProcessMonitor:', error);
      }
    }

    // Start File Monitor
    if (settings.fileMonitoring) {
      try {
        await FileMonitorEngine.start();
        store.dispatch(setEngineStatus({fileMonitor: true}));
      } catch (error) {
        console.error('EngineManager: Failed to start FileMonitor:', error);
      }
    }

    // Start Network Monitor
    if (settings.networkMonitoring) {
      try {
        await NetworkMonitorEngine.start();
        store.dispatch(setEngineStatus({networkMonitor: true}));
      } catch (error) {
        console.error('EngineManager: Failed to start NetworkMonitor:', error);
      }
    }

    // Start Phishing Detector
    if (settings.phishingDetection) {
      try {
        await PhishingDetectorEngine.start();
        store.dispatch(setEngineStatus({phishingDetector: true}));
      } catch (error) {
        console.error('EngineManager: Failed to start PhishingDetector:', error);
      }
    }

    console.log('EngineManager: All engines started');
  }

  /**
   * Stop all engines
   */
  async stop(): Promise<void> {
    console.log('EngineManager: Stopping all engines...');

    const stopPromises = Array.from(this.engines.values()).map(async engine => {
      try {
        await engine.stop();
      } catch (error) {
        console.error('EngineManager: Error stopping engine:', error);
      }
    });

    await Promise.all(stopPromises);

    store.dispatch(
      setEngineStatus({
        processMonitor: false,
        fileMonitor: false,
        networkMonitor: false,
        phishingDetector: false,
        malwareSandbox: false,
        llmExplainer: false,
      }),
    );

    console.log('EngineManager: All engines stopped');
  }

  /**
   * Get engine by name
   */
  getEngine(name: string): IEngine | undefined {
    return this.engines.get(name);
  }

  /**
   * Get status of all engines
   */
  getAllEngineStatus(): Map<string, any> {
    const status = new Map();
    for (const [name, engine] of this.engines.entries()) {
      status.set(name, engine.getStatus());
    }
    return status;
  }
}

export default new EngineManager();
