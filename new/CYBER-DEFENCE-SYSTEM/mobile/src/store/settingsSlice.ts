import { createSlice, PayloadAction } from '@reduxjs/toolkit';

interface SettingsState {
  enableFileMonitoring: boolean;
  enableProcessMonitoring: boolean;
  enableNetworkMonitoring: boolean;
  dataRetentionDays: number;
  autoStartOnBoot: boolean;
  notificationsEnabled: boolean;
  theme: 'dark' | 'light';
  language: string;
}

const initialState: SettingsState = {
  enableFileMonitoring: true,
  enableProcessMonitoring: true,
  enableNetworkMonitoring: true,
  dataRetentionDays: 30,
  autoStartOnBoot: true,
  notificationsEnabled: true,
  theme: 'dark',
  language: 'en',
};

export const settingsSlice = createSlice({
  name: 'settings',
  initialState,
  reducers: {
    setFileMonitoring: (state, action: PayloadAction<boolean>) => {
      state.enableFileMonitoring = action.payload;
    },
    setProcessMonitoring: (state, action: PayloadAction<boolean>) => {
      state.enableProcessMonitoring = action.payload;
    },
    setNetworkMonitoring: (state, action: PayloadAction<boolean>) => {
      state.enableNetworkMonitoring = action.payload;
    },
    setDataRetention: (state, action: PayloadAction<number>) => {
      state.dataRetentionDays = action.payload;
    },
    setAutoStart: (state, action: PayloadAction<boolean>) => {
      state.autoStartOnBoot = action.payload;
    },
    setNotifications: (state, action: PayloadAction<boolean>) => {
      state.notificationsEnabled = action.payload;
    },
    setTheme: (state, action: PayloadAction<'dark' | 'light'>) => {
      state.theme = action.payload;
    },
    setLanguage: (state, action: PayloadAction<string>) => {
      state.language = action.payload;
    },
  },
});

export const {
  setFileMonitoring,
  setProcessMonitoring,
  setNetworkMonitoring,
  setDataRetention,
  setAutoStart,
  setNotifications,
  setTheme,
  setLanguage,
} = settingsSlice.actions;

export default settingsSlice.reducer;
