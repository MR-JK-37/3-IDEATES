/**
 * Redux slice for threat management
 */

import {createSlice, PayloadAction} from '@reduxjs/toolkit';
import {Threat, ThreatType, ThreatLevel} from '../../types';

interface ThreatsState {
  items: Threat[];
  activeThreats: Threat[];
  history: Threat[];
  totalBlocked: number;
  lastUpdate: number;
}

const initialState: ThreatsState = {
  items: [],
  activeThreats: [],
  history: [],
  totalBlocked: 0,
  lastUpdate: Date.now(),
};

const threatsSlice = createSlice({
  name: 'threats',
  initialState,
  reducers: {
    addThreat: (state, action: PayloadAction<Threat>) => {
      const threat = action.payload;
      state.items.push(threat);
      
      if (!threat.blocked) {
        state.activeThreats.push(threat);
      } else {
        state.totalBlocked += 1;
      }
      
      state.history.push(threat);
      state.lastUpdate = Date.now();
      
      // Keep only last 1000 threats in history
      if (state.history.length > 1000) {
        state.history = state.history.slice(-1000);
      }
    },
    updateThreat: (state, action: PayloadAction<{id: string; updates: Partial<Threat>}>) => {
      const {id, updates} = action.payload;
      const index = state.items.findIndex(t => t.id === id);
      
      if (index !== -1) {
        state.items[index] = {...state.items[index], ...updates};
        
        // Update active threats if blocked
        if (updates.blocked) {
          state.activeThreats = state.activeThreats.filter(t => t.id !== id);
          state.totalBlocked += 1;
        }
      }
    },
    removeThreat: (state, action: PayloadAction<string>) => {
      const id = action.payload;
      state.items = state.items.filter(t => t.id !== id);
      state.activeThreats = state.activeThreats.filter(t => t.id !== id);
    },
    clearHistory: state => {
      state.history = [];
      state.totalBlocked = 0;
    },
    setActiveThreats: (state, action: PayloadAction<Threat[]>) => {
      state.activeThreats = action.payload;
    },
  },
});

export const {addThreat, updateThreat, removeThreat, clearHistory, setActiveThreats} =
  threatsSlice.actions;
export default threatsSlice.reducer;
