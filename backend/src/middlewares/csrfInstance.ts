import { createCsrfMiddleware } from './csrfMiddleware';
import logger from '../utils/logger';

// Create a single shared instance of the CSRF middleware
// This ensures token generation and validation use the same in-memory store
export const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();

logger.info('CSRF middleware instance initialized (shared)');
