/**
 * Base interface for all security engines
 */

export interface IEngine {
  /**
   * Initialize the engine
   */
  initialize(): Promise<void>;

  /**
   * Start monitoring
   */
  start(): Promise<void>;

  /**
   * Stop monitoring
   */
  stop(): Promise<void>;

  /**
   * Check if engine is running
   */
  isRunning(): boolean;

  /**
   * Get engine status
   */
  getStatus(): EngineStatus;
}

export interface EngineStatus {
  running: boolean;
  lastScanTime: number;
  threatsDetected: number;
  errors: string[];
}
