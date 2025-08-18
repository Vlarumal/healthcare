import { useState, useEffect } from 'react';
import { AuthContext } from './AuthContextObject';
import type { ReactNode } from 'react';
import { AuthService } from '../services/authService';
import type { User } from '../types/auth';
import { ERROR_CODES } from '../constants/errors';
import { isAxiosErrorWithCode } from '../utils/errorUtils';
import {
  setupApiInterceptors,
  setGlobalLogoutHandler,
} from '../services/apiRequest';

export const AuthProvider = ({
  children,
}: {
  children: ReactNode;
}) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setupApiInterceptors(logout);
    setGlobalLogoutHandler(logout);

    const initAuth = async () => {
      try {
        // Initialize API interceptors only, don't fetch CSRF token upfront
        // CSRF token will be fetched lazily when needed

        const storedUser = localStorage.getItem('authState');
        if (storedUser) {
          const isValid = await AuthService.validateToken();
          if (isValid) {
            setUser(JSON.parse(storedUser));
          } else {
            localStorage.removeItem('authState');
          }
        }
      } catch (err: unknown) {
        const message =
          err instanceof Error
            ? err.message
            : 'Failed to initialize authentication';
        setError(message);
        if (import.meta.env.DEV) {
          console.error('Auth initialization error:', err);
        }
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, []);

  const login = async (email: string, password: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const currentUser = await AuthService.login({
        email,
        password,
      });

      await new Promise<void>((resolve) => {
        setUser(currentUser);

        localStorage.setItem(
          'authState',
          JSON.stringify(currentUser)
        );

        setTimeout(() => resolve(), 0);
      });

      return currentUser;
    } catch (err) {
      let errorMessage =
        'Login failed. Please check your credentials.';

      if (isAxiosErrorWithCode(err, ERROR_CODES.CSRF_TIMEOUT_ERROR)) {
        errorMessage =
          'Network timeout. Please check your connection and try again.';
      }

      setError(errorMessage);
      setUser(null);
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setUser(null);
    localStorage.removeItem('authState');
    await AuthService.logout();
  };

  const value = {
    user,
    isAuthenticated: !!user,
    isLoading,
    error,
    login,
    logout,
    userRole: user?.role,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
