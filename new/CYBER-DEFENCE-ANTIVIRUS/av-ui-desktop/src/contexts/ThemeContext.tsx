import { createContext, useContext, useLayoutEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

export type Theme = 'light' | 'dark' | 'cyberpunk';

type ThemeContextValue = {
  theme: Theme;
  setTheme: (nextTheme: Theme) => void;
};

const STORAGE_KEY = 'cybershield-theme';
const isTauriRuntime = '__TAURI_IPC__' in (window as unknown as Record<string, unknown>);

const ThemeContext = createContext<ThemeContextValue | null>(null);

function applyTheme(theme: Theme) {
  document.documentElement.setAttribute('data-theme', theme);
  document.body.setAttribute('data-theme', theme);
}

function resolveInitialTheme(): Theme {
  const saved = window.localStorage.getItem(STORAGE_KEY) as Theme | null;
  if (saved === 'light' || saved === 'dark' || saved === 'cyberpunk') {
    return saved;
  }
  return 'dark';
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => resolveInitialTheme());

  useLayoutEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = (nextTheme: Theme) => {
    setThemeState(nextTheme);
    window.localStorage.setItem(STORAGE_KEY, nextTheme);
    if (isTauriRuntime) {
      void invoke('set_theme', { theme: nextTheme }).catch(() => {});
    }
  };

  const value = useMemo(() => ({ theme, setTheme }), [theme]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return context;
}
