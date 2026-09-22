import { createSlice, PayloadAction } from '@reduxjs/toolkit';

interface Threat {
  id: string;
  timestamp: string;
  type: 'process' | 'file' | 'network' | 'system';
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  details: string;
  mitigated?: boolean;
}

interface ThreatState {
  items: Threat[];
  isMonitoring: boolean;
  lastUpdate: number;
  filter: {
    type?: string;
    severity?: string;
    source?: string;
  };
}

const initialState: ThreatState = {
  items: [],
  isMonitoring: false,
  lastUpdate: 0,
  filter: {},
};

export const threatSlice = createSlice({
  name: 'threats',
  initialState,
  reducers: {
    setThreats: (state, action: PayloadAction<Threat[]>) => {
      state.items = action.payload;
      state.lastUpdate = Date.now();
    },
    addThreat: (state, action: PayloadAction<Threat>) => {
      state.items.unshift(action.payload);
      state.lastUpdate = Date.now();
    },
    removeThreat: (state, action: PayloadAction<string>) => {
      state.items = state.items.filter(t => t.id !== action.payload);
    },
    setMonitoring: (state, action: PayloadAction<boolean>) => {
      state.isMonitoring = action.payload;
    },
    setFilter: (state, action: PayloadAction<ThreatState['filter']>) => {
      state.filter = action.payload;
    },
    clearThreats: (state) => {
      state.items = [];
    },
  },
});

export const { setThreats, addThreat, removeThreat, setMonitoring, setFilter, clearThreats } = threatSlice.actions;

export default threatSlice.reducer;
