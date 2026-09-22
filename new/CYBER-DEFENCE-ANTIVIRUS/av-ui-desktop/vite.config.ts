import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],
  
  // Vite options tailored for Tauri CLI usage
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: {
      // Using file watching instead of polling since that's faster
      usePolling: false,
    },
  },
  build: {
    target: 'ES2020',
    minify: 'esbuild',
    rollupOptions: {
      output: {
        manualChunks: {
          'recharts-vendor': ['recharts'],
        },
      },
    },
  },
}));
