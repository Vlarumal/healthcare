import { apiRequest } from './apiRequest';
import { logout as performLogout } from './logoutService';
import { ERROR_CODES } from '../constants/errors';
import { hasIsTimeout, isAxiosErrorWithCode } from '../utils/errorUtils';
import type {
  LoginCredentials,
  SignupCredentials,
  User,
} from '../types/auth';

export const AuthService = {
  async signup(credentials: SignupCredentials): Promise<void> {
    await apiRequest('POST', '/api/auth/signup', {
      firstName: credentials.firstName,
      lastName: credentials.lastName,
      email: credentials.email,
      password: credentials.password,
      dateOfBirth: credentials.dateOfBirth
    });
  },

  async login(credentials: LoginCredentials): Promise<User> {
    try {
      const response = await apiRequest<User>(
        'POST',
        '/api/auth/login',
        credentials
      );
      return response;
    } catch (error: unknown) {
      if (isAxiosErrorWithCode(error, 'ECONNABORTED') || hasIsTimeout(error)) {
        throw Object.assign(new Error('Connection timeout - please check your network and try again'), {
          code: ERROR_CODES.CSRF_TIMEOUT_ERROR,
          isTimeout: true,
          cause: error
        });
      }
      throw error;
    }
  },

  logout: performLogout,

  async getCurrentUser(): Promise<User | null> {
    try {
      return await apiRequest('GET', '/api/auth/me') as User;
    } catch (error: unknown) {
      console.error('Error fetching current user:', error);
      return null;
    }
  },

  isAuthenticated(): Promise<boolean> {
    return this.getCurrentUser()
      .then((user) => !!user)
      .catch(() => false);
  },

  validateToken: async (): Promise<boolean> => {
    try {
      await apiRequest('GET', '/api/auth/validate-token');
      return true;
    } catch {
      return false;
    }
  },
};
