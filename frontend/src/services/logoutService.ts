import { apiRequest } from './apiRequest';
import { ERROR_CODES } from '../constants/errors';
import { hasIsTimeout, isAxiosErrorWithCode } from '../utils/errorUtils';

export const logout = async () => {
  try {
    try {
      await apiRequest('POST', '/api/auth/refresh');
    } catch (refreshError) {
      console.warn('Token refresh before logout failed, proceeding anyway', refreshError);
    }
    
    await apiRequest('POST', '/api/auth/logout');
    // resetCsrfToken();
  } catch (error: unknown) {
    if (isAxiosErrorWithCode(error, 'ECONNABORTED') || hasIsTimeout(error)) {
      throw Object.assign(new Error(ERROR_CODES.CSRF_TIMEOUT_ERROR), {
        code: ERROR_CODES.CSRF_TIMEOUT_ERROR,
        isTimeout: true,
        cause: error
      });
    }
    if (import.meta.env.DEV) {
      console.error('Logout failed', error);
    }
    throw error;
  } finally {
    window.dispatchEvent(
      new CustomEvent('authChange', {
        detail: { isAuthenticated: false },
      })
    );
  }
};