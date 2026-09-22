import { createSlice, PayloadAction } from '@reduxjs/toolkit';

interface NetworkConnection {
  id: string;
  sourceIp: string;
  destIp: string;
  destPort: number;
  protocol: string;
  appName: string;
  bytesTransferred: number;
  isBlocked: boolean;
  timestamp: string;
}

interface NetworkState {
  connections: NetworkConnection[];
  blockedCount: number;
  suspiciousCount: number;
  enableNetworkMonitoring: boolean;
}

const initialState: NetworkState = {
  connections: [],
  blockedCount: 0,
  suspiciousCount: 0,
  enableNetworkMonitoring: true,
};

export const networkSlice = createSlice({
  name: 'network',
  initialState,
  reducers: {
    setConnections: (state, action: PayloadAction<NetworkConnection[]>) => {
      state.connections = action.payload;
      state.blockedCount = action.payload.filter(c => c.isBlocked).length;
      state.suspiciousCount = action.payload.filter(c => c.destPort > 50000).length;
    },
    addConnection: (state, action: PayloadAction<NetworkConnection>) => {
      state.connections.unshift(action.payload);
      if (action.payload.isBlocked) state.blockedCount++;
    },
    blockConnection: (state, action: PayloadAction<string>) => {
      const conn = state.connections.find(c => c.id === action.payload);
      if (conn && !conn.isBlocked) {
        conn.isBlocked = true;
        state.blockedCount++;
      }
    },
    setNetworkMonitoring: (state, action: PayloadAction<boolean>) => {
      state.enableNetworkMonitoring = action.payload;
    },
  },
});

export const { setConnections, addConnection, blockConnection, setNetworkMonitoring } = networkSlice.actions;

export default networkSlice.reducer;
