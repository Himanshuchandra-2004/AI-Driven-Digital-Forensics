/** Dark / light theme switch (persists in localStorage, sets <html data-theme>). */
import { useEffect, useState } from 'react';
import { Moon, Sun } from 'lucide-react';

export default function ThemeToggle() {
  const [theme, setTheme] = useState<'dark' | 'light'>(
    () => (localStorage.getItem('theme') as 'dark' | 'light') || 'dark'
  );
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('theme', theme);
  }, [theme]);
  return (
    <button
      type="button"
      className={`theme-toggle ${theme}`}
      onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
      aria-label="Toggle light / dark theme"
      title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
    >
      <Moon size={14} /><Sun size={14} /><span className="knob" />
    </button>
  );
}
