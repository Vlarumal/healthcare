import axios, { type AxiosRequestConfig } from 'axios';

/**
 * Secure API request service with:
 * - CSRF protection (cookie-based only)
 * - Token refresh with backoff limiting
 * - Standardized error handling
 *
 */
const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  withCredentials: true,
});

// let csrfToken: string | null = null;
// let csrfTokenPromise: Promise<string> | null = null;

// export const resetCsrfToken = () => {
//   csrfToken = null;
//   csrfTokenPromise = null;
// };

// Centralized error handler
function handleApiError(
  error: unknown,
  method: string,
  endpoint: string
): Error {
  let message = 'Request failed';
  let code = 'UNKNOWN_ERROR';

  if (axios.isAxiosError(error)) {
    if (import.meta.env.DEV) {
      console.error('API Request Failed:', {
        endpoint,
        method,
        error: error.message,
        response: error.response?.data,
      });
    }

    const errorData = error.response?.data;

    if (typeof errorData === 'string') {
      message = errorData;
    } else if (errorData?.error?.message) {
      message = errorData.error.message;
      code = errorData.error.code || code;
    } else if (errorData?.message) {
      message = errorData.message;
      code = errorData.code || code;
    }
  } else if (error instanceof Error) {
    if (import.meta.env.DEV) {
      console.error('API Request Failed:', {
        endpoint,
        method,
        error: error.message,
      });
    }
    message = error.message;
  } else {
    if (import.meta.env.DEV) {
      console.error('Unknown API error:', error);
    }
    message = String(error);
  }

  const enhancedError = new Error(message, { cause: error });
  enhancedError.name = code;

  const fallbackMessages: Record<string, string> = {
    INVALID_TOKEN: 'Your session has expired - please login again',
    TOKEN_REVOKED: 'Session invalidated - please reauthenticate',
    CREDENTIALS_CHANGED: 'Credentials changed - please login again',
    INVALID_CSRF_TOKEN: 'Security token expired - refreshing...',
  };

  if (fallbackMessages[code]) {
    enhancedError.message = fallbackMessages[code];
  }

  throw enhancedError;
}

interface ExtendedAxiosRequestConfig extends AxiosRequestConfig {
  _retry?: boolean;
}

// const fetchCsrfToken = async (): Promise<string> => {
//   try {
//     const response = await apiClient.get('/api/csrf-token', {
//       timeout: 5000,
//     });
//     const token = response.data.csrfToken;
//     if (typeof token !== 'string') {
//       throw new Error('Invalid CSRF token format');
//     }
//     return token;
//   } catch (err) {
//     if (axios.isAxiosError(err) && err.code === 'ECONNABORTED') {
//       throw Object.assign(new Error(`CSRF token request timed out`), {
//         code: 'ECONNABORTED',
//         isTimeout: true,
//       });
//     }

//     throw err;
//   }
// };

// export const getCsrfToken = async (): Promise<string> => {
//   if (csrfToken) {
//     return csrfToken;
//   }

//   if (csrfTokenPromise) {
//     return csrfTokenPromise;
//   }

//   csrfTokenPromise = fetchCsrfToken()
//     .then((token) => {
//       csrfToken = token;
//       return token;
//     })
//     .catch((err) => {
//       if (err.code === 'ECONNABORTED' && err.isTimeout) {
//         throw Object.assign(
//           new Error(`Failed to retrieve CSRF token: ${err.message}`),
//           {
//             code: err.code,
//             isTimeout: true,
//           }
//         );
//       }

//       const enhancedError = new Error(
//         `Failed to retrieve CSRF token: ${err.message}`,
//         { cause: err }
//       );
//       enhancedError.name = err.name || 'CSRF_ERROR';

//       const rest = Object.fromEntries(
//         Object.entries(err).filter(
//           ([key]) => key !== 'message' && key !== 'name'
//         )
//       );
//       Object.assign(enhancedError, rest);
//       throw enhancedError;
//     })
//     .finally(() => {
//       csrfTokenPromise = null;
//     });

//   return csrfTokenPromise;
// };

let globalLogoutHandler: (() => Promise<void>) | null = null;

export const setGlobalLogoutHandler = (
  logoutCallback: () => Promise<void>
) => {
  globalLogoutHandler = logoutCallback;
};

export const setupApiInterceptors = (
  logoutHandler: () => Promise<void>
) => {
  globalLogoutHandler = logoutHandler;
  apiClient.interceptors.request.use(async (config) => {
    if (
      !['get', 'head', 'options'].includes(
        config.method?.toLowerCase() || ''
      )
    ) {
      // const token = await getCsrfToken();
      // config.headers['x-csrf-token'] = token;
    }
    return config;
  });

  apiClient.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config;

      if (import.meta.env.DEV) {
        if (error.response) {
          console.error('API Error:', {
            status: error.response.status,
            url: originalRequest.url,
            code: error.response.data?.code,
            message: error.response.data?.message,
          });
        } else {
          console.error('Network Error:', error.message);
        }
      }

      if (
        error.response?.status === 403 &&
        (error.response.data?.code === 'EBADCSRFTOKEN' ||
          error.response.data?.code === 'INVALID_CSRF_TOKEN' ||
          error.response.data?.code ===
            'CSRF_TOKEN_MISSING_OR_INVALID')
      ) {
        // try {
        //   const { csrfToken } = await apiRequest<{
        //     csrfToken: string;
        //   }>('GET', '/api/csrf-token');

        //   if (csrfToken) {
        //     originalRequest.headers['x-csrf-token'] = csrfToken;
        //     return apiClient(originalRequest);
        //   }
        // } catch (refreshError) {
        //   if (import.meta.env.DEV) {
        //     console.error('CSRF refresh failed:', refreshError);
        //   }
        // }
      }

      if (
        error.response?.status === 401 &&
        !(originalRequest as ExtendedAxiosRequestConfig)._retry
      ) {
        (originalRequest as ExtendedAxiosRequestConfig)._retry = true;
        try {
          // Attempt silent refresh
          await apiClient.post(
            '/api/auth/refresh',
            {},
            { withCredentials: true }
          );
          return apiClient(originalRequest);
        } catch {
          if (globalLogoutHandler) {
            await globalLogoutHandler();
          } else {
            console.error('Global logout handler not set!');
          }
          return Promise.reject(
            new Error('Session expired - please login again')
          );
        }
      }

      return Promise.reject(error);
    }
  );
};

export const apiRequest = async <T>(
  method: string,
  endpoint: string,
  data?: unknown
): Promise<T> => {
  const resolvedEndpoint =
    endpoint === '/patients/me' ? '/patients/me' : endpoint;

  try {
    const response = await apiClient.request({
      method,
      url: resolvedEndpoint,
      data,
      validateStatus: (status) =>
        (status >= 200 && status < 300) || status === 401,
    });
    return response.data;
  } catch (error: unknown) {
    throw handleApiError(error, method, resolvedEndpoint);
  }
};
