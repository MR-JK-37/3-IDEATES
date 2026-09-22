/**
 * Redux slice for process monitoring
 */

import {createSlice, PayloadAction} from '@reduxjs/toolkit';
import {ProcessInfo} from '../../types';

interface ProcessesState {
  processes: ProcessInfo[];
  suspiciousProcesses: ProcessInfo[];
  lastUpdate: number;
}

const initialState: ProcessesState = {
  processes: [],
  suspiciousProcesses: [],
  lastUpdate: Date.now(),
};

const processesSlice = createSlice({
  name: 'processes',
  initialState,
  reducers: {
    setProcesses: (state, action: PayloadAction<ProcessInfo[]>) => {
      state.processes = action.payload;
      state.suspiciousProcesses = action.payload.filter(p => p.riskScore > 50);
      state.lastUpdate = Date.now();
    },
    updateProcess: (state, action: PayloadAction<ProcessInfo>) => {
      const index = state.processes.findIndex(p => p.pid === action.payload.pid);
      if (index !== -1) {
        state.processes[index] = action.payload;
      } else {
        state.processes.push(action.payload);
      }
      
      // Update suspicious processes list
      state.suspiciousProcesses = state.processes.filter(p => p.riskScore > 50);
      state.lastUpdate = Date.now();
    },
    removeProcess: (state, action: PayloadAction<number>) => {
      state.processes = state.processes.filter(p => p.pid !== action.payload);
      state.suspiciousProcesses = state.suspiciousProcesses.filter(p => p.pid !== action.payload);
      state.lastUpdate = Date.now();
    },
  },
});

export const {setProcesses, updateProcess, removeProcess} = processesSlice.actions;
export default processesSlice.reducer;
