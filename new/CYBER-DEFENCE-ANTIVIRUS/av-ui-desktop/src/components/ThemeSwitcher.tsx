import { useTheme, type Theme } from '../contexts/ThemeContext';

const themeOptions: { value: Theme; icon: string; label: string }[] = [
  { value: 'light', icon: 'Light', label: 'Light' },
  { value: 'dark', icon: 'Dark', label: 'Dark' },
  { value: 'cyberpunk', icon: 'Neon', label: 'Cyberpunk' },
];

export default function ThemeSwitcher() {
  const { theme, setTheme } = useTheme();

  return (
    <div className="theme-switcher" role="group" aria-label="Theme selector">
      {themeOptions.map((option) => (
        <button
          key={option.value}
          type="button"
          className={`theme-switcher-btn ${theme === option.value ? 'active' : ''}`}
          onClick={() => setTheme(option.value)}
        >
          <span>{option.icon}</span>
          <span>{option.label}</span>
        </button>
      ))}
    </div>
  );
}
