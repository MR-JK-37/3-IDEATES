import { createSlice, PayloadAction } from '@reduxjs/toolkit';

interface Process {
  pid: number;
  name: string;
  packageName: string;
  riskScore: number;
  permissions: string[];
  memoryUsage: number;
  isSystemApp: boolean;
}

interface ProcessState {
  items: Process[];
  selectedPid?: number;
  sortBy: 'risk' | 'memory' | 'name';
}

const initialState: ProcessState = {
  items: [],
  sortBy: 'risk',
};

export const processSlice = createSlice({
  name: 'processes',
  initialState,
  reducers: {
    setProcesses: (state, action: PayloadAction<Process[]>) => {
      state.items = action.payload;
    },
    updateProcess: (state, action: PayloadAction<Process>) => {
      const index = state.items.findIndex(p => p.pid === action.payload.pid);
      if (index >= 0) {
        state.items[index] = action.payload;
      }
    },
    removeProcess: (state, action: PayloadAction<number>) => {
      state.items = state.items.filter(p => p.pid !== action.payload);
    },
    setSelectedProcess: (state, action: PayloadAction<number | undefined>) => {
      state.selectedPid = action.payload;
    },
    setSortBy: (state, action: PayloadAction<'risk' | 'memory' | 'name'>) => {
      state.sortBy = action.payload;
    },
  },
});

export const { setProcesses, updateProcess, removeProcess, setSelectedProcess, setSortBy } = processSlice.actions;

export default processSlice.reducer;
