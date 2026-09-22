import { configureStore } from '@reduxjs/toolkit';
import threatReducer from './threatSlice';
import processReducer from './processSlice';
import networkReducer from './networkSlice';
import settingsReducer from './settingsSlice';

export const store = configureStore({
  reducer: {
    threats: threatReducer,
    processes: processReducer,
    network: networkReducer,
    settings: settingsReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
