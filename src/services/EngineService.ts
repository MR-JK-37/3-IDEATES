/**
 * Engine Service
 * Initializes and manages security engines on app start
 */

import EngineManager from '../engine/EngineManager';
import DatabaseManager from '../database/DatabaseManager';
import {store} from '../store';
import {setProtectionStatus} from '../store/slices/systemHealthSlice';
import {ProtectionStatus} from '../types';

class EngineService {
  private initialized: boolean = false;

  /**
   * Initialize all services
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      console.warn('EngineService: Already initialized');
      return;
    }

    try {
      console.log('EngineService: Initializing services...');

      // Initialize database
      await DatabaseManager.initialize();
      console.log('EngineService: Database initialized');

      // Initialize engines
      await EngineManager.initialize();
      console.log('EngineService: Engines initialized');

      // Start engines based on settings
      const settings = store.getState().settings;
      if (
        settings.processMonitoring ||
        settings.fileMonitoring ||
        settings.networkMonitoring ||
        settings.phishingDetection
      ) {
        await EngineManager.start();
        store.dispatch(setProtectionStatus(ProtectionStatus.ACTIVE));
        console.log('EngineService: Engines started');
      } else {
        store.dispatch(setProtectionStatus(ProtectionStatus.INACTIVE));
      }

      this.initialized = true;
    } catch (error) {
      console.error('EngineService: Initialization error:', error);
      store.dispatch(setProtectionStatus(ProtectionStatus.ERROR));
      throw error;
    }
  }

  /**
   * Start all engines
   */
  async start(): Promise<void> {
    await EngineManager.start();
    store.dispatch(setProtectionStatus(ProtectionStatus.ACTIVE));
  }

  /**
   * Stop all engines
   */
  async stop(): Promise<void> {
    await EngineManager.stop();
    store.dispatch(setProtectionStatus(ProtectionStatus.INACTIVE));
  }
}

export default new EngineService();
