/**
 * Redux Store Configuration
 */

import {configureStore} from '@reduxjs/toolkit';
import threatsReducer from './slices/threatsSlice';
import systemHealthReducer from './slices/systemHealthSlice';
import settingsReducer from './slices/settingsSlice';
import processesReducer from './slices/processesSlice';

export const store = configureStore({
  reducer: {
    threats: threatsReducer,
    systemHealth: systemHealthReducer,
    settings: settingsReducer,
    processes: processesReducer,
  },
  middleware: getDefaultMiddleware =>
    getDefaultMiddleware({
      serializableCheck: {
        // Ignore these action types
        ignoredActions: ['threats/addThreat', 'threats/updateThreat'],
        // Ignore these field paths in all actions
        ignoredActionPaths: ['meta.arg', 'payload.timestamp'],
        // Ignore these paths in the state
        ignoredPaths: ['threats.items'],
      },
    }),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
