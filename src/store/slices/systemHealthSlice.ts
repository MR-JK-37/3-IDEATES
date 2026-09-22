/**
 * Redux slice for system health monitoring
 */

import {createSlice, PayloadAction} from '@reduxjs/toolkit';
import {SystemHealth, ProtectionStatus, EngineStatus} from '../../types';

const initialState: SystemHealth = {
  protectionStatus: ProtectionStatus.INACTIVE,
  activeThreats: 0,
  threatsBlockedToday: 0,
  lastScanTime: 0,
  cpuUsage: 0,
  memoryUsage: 0,
  batteryImpact: 0,
  engineStatus: {
    processMonitor: false,
    fileMonitor: false,
    networkMonitor: false,
    phishingDetector: false,
    malwareSandbox: false,
    llmExplainer: false,
  },
};

const systemHealthSlice = createSlice({
  name: 'systemHealth',
  initialState,
  reducers: {
    updateSystemHealth: (state, action: PayloadAction<Partial<SystemHealth>>) => {
      return {...state, ...action.payload};
    },
    setProtectionStatus: (state, action: PayloadAction<ProtectionStatus>) => {
      state.protectionStatus = action.payload;
    },
    setEngineStatus: (state, action: PayloadAction<Partial<EngineStatus>>) => {
      state.engineStatus = {...state.engineStatus, ...action.payload};
    },
    incrementThreatsBlocked: state => {
      state.threatsBlockedToday += 1;
    },
    updateResourceUsage: (
      state,
      action: PayloadAction<{cpuUsage: number; memoryUsage: number; batteryImpact: number}>,
    ) => {
      state.cpuUsage = action.payload.cpuUsage;
      state.memoryUsage = action.payload.memoryUsage;
      state.batteryImpact = action.payload.batteryImpact;
    },
  },
});

export const {
  updateSystemHealth,
  setProtectionStatus,
  setEngineStatus,
  incrementThreatsBlocked,
  updateResourceUsage,
} = systemHealthSlice.actions;
export default systemHealthSlice.reducer;
