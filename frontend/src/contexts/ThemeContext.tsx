import { useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';
import { ThemeProvider as MuiThemeProvider } from '@mui/material/styles';
import theme, { darkTheme } from '../theme';
import { ThemeContext } from './ThemeContextObject';

export const ThemeProvider = ({
  children,
}: {
  children: ReactNode;
}) => {
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    try {
      const savedTheme = localStorage.getItem('themePreference');
      if (savedTheme !== null) {
        return JSON.parse(savedTheme);
      }
      return window.matchMedia('(prefers-color-scheme: dark)').matches;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Error reading theme preference:', error);
      }
      return false;
    }
  });

  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'themePreference') {
        try {
          const newValue = JSON.parse(e.newValue || 'null');
          setDarkMode(newValue);
        } catch (error) {
          if (import.meta.env.DEV) {
            console.error('Error parsing theme preference from storage event:', error);
          }
        }
      }
    };

    window.addEventListener('storage', handleStorageChange);
    
    return () => {
      window.removeEventListener('storage', handleStorageChange);
    };
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem('themePreference', JSON.stringify(darkMode));
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Error saving theme preference:', error);
      }
    }
  }, [darkMode]);

  const toggleTheme = useCallback(() => {
    setDarkMode(prevMode => !prevMode);
  }, []);

  return (
    <ThemeContext.Provider value={{ darkMode, toggleTheme }}>
      <MuiThemeProvider theme={darkMode ? darkTheme : theme}>
        {children}
      </MuiThemeProvider>
    </ThemeContext.Provider>
  );
};
/**
 * ThemeContext Documentation
 *
 * Provides theme management for the application using React Context API.
 *
 * Features:
 * - Toggle between light/dark modes
 * - Persists user preference in localStorage
 * - Integrates with Material-UI theming
 *
 * Usage:
 * 1. Wrap your app with ThemeProvider
 * 2. Use the useTheme hook in components:
 *    const { darkMode, toggleTheme } = useTheme();
 *
 * The theme will automatically persist between sessions.
 */
