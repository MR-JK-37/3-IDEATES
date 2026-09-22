/**
 * Redux slice for application settings
 */

import {createSlice, PayloadAction} from '@reduxjs/toolkit';
import {AppSettings} from '../../types';

const initialState: AppSettings = {
  processMonitoring: true,
  fileMonitoring: true,
  networkMonitoring: true,
  phishingDetection: true,
  malwareSandbox: true,
  sensitivityLevel: 'MEDIUM',
  notificationsEnabled: true,
  hapticFeedback: true,
  darkMode: true,
  excludedPackages: [],
  excludedPaths: [],
};

const settingsSlice = createSlice({
  name: 'settings',
  initialState,
  reducers: {
    updateSettings: (state, action: PayloadAction<Partial<AppSettings>>) => {
      return {...state, ...action.payload};
    },
    toggleFeature: (state, action: PayloadAction<keyof AppSettings>) => {
      const key = action.payload;
      if (typeof state[key] === 'boolean') {
        (state[key] as boolean) = !(state[key] as boolean);
      }
    },
    setSensitivityLevel: (state, action: PayloadAction<'LOW' | 'MEDIUM' | 'HIGH'>) => {
      state.sensitivityLevel = action.payload;
    },
    addExcludedPackage: (state, action: PayloadAction<string>) => {
      if (!state.excludedPackages.includes(action.payload)) {
        state.excludedPackages.push(action.payload);
      }
    },
    removeExcludedPackage: (state, action: PayloadAction<string>) => {
      state.excludedPackages = state.excludedPackages.filter(p => p !== action.payload);
    },
    addExcludedPath: (state, action: PayloadAction<string>) => {
      if (!state.excludedPaths.includes(action.payload)) {
        state.excludedPaths.push(action.payload);
      }
    },
    removeExcludedPath: (state, action: PayloadAction<string>) => {
      state.excludedPaths = state.excludedPaths.filter(p => p !== action.payload);
    },
  },
});

export const {
  updateSettings,
  toggleFeature,
  setSensitivityLevel,
  addExcludedPackage,
  removeExcludedPackage,
  addExcludedPath,
  removeExcludedPath,
} = settingsSlice.actions;
export default settingsSlice.reducer;
