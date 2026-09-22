/**
 * Native Modules Bridge
 * Provides TypeScript interfaces for React Native native modules
 */

import {NativeModules, NativeEventEmitter} from 'react-native';

interface ProcessMonitorModule {
  getRunningProcesses(): Promise<Array<{
    pid: number;
    name: string;
    pids: number[];
    cpuUsage: number;
    memoryUsage: number;
    isHidden: boolean;
  }>>;
}

interface FileMonitorModule {
  startWatching(path: string): Promise<boolean>;
  stopWatching(): Promise<boolean>;
  scanForAPKs(path: string): Promise<Array<{path: string; size: number}>>;
}

interface NetworkMonitorModule {
  startVpnService(): Promise<boolean>;
  stopVpnService(): Promise<boolean>;
}

// Get native modules
const {ProcessMonitorModule, FileMonitorModule, NetworkMonitorModule} = NativeModules;

// Create event emitters
export const processMonitorEvents = ProcessMonitorModule
  ? new NativeEventEmitter(ProcessMonitorModule)
  : null;

export const fileMonitorEvents = FileMonitorModule
  ? new NativeEventEmitter(FileMonitorModule)
  : null;

export const networkMonitorEvents = NetworkMonitorModule
  ? new NativeEventEmitter(NetworkMonitorModule)
  : null;

// Export typed modules
export const ProcessMonitor = ProcessMonitorModule as ProcessMonitorModule | null;
export const FileMonitor = FileMonitorModule as FileMonitorModule | null;
export const NetworkMonitor = NetworkMonitorModule as NetworkMonitorModule | null;
