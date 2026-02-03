/**
 * Test App Factory
 * 
 * Creates an Express application configured for testing.
 * Provides a clean app instance with all routes and standard middleware.
 * Dependencies should be mocked using jest.mock() in individual test files.
 * 
 * @module test-utils/appFactory
 */

import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import authRoutes from '../routes/authRoutes';
import patientRoutes from '../routes/patientRoutes';
import medicalHistoryRoutes from '../routes/medicalHistoryRoutes';
import dashboardRoutes from '../routes/dashboardRoutes';
import errorHandler from '../middlewares/errorHandler';

/**
 * Creates an Express app configured for testing
 * 
 * This function sets up an Express application with all routes and
 * standard middleware used in production. Test files can then add
 * their specific mocks and additional middleware as needed.
 * 
 * The app includes:
 * - JSON body parsing
 * - Cookie parsing
 * - All application routes (/api/auth, /api/patients, /api/medical-history, /api/dashboard)
 * - Error handler middleware
 * 
 * @param setupCallback Optional callback to customize the app with additional routes/middleware
 * @returns Express application ready for testing
 * 
 * @example
 * ```typescript
 * // In a test file
 * import { createTestApp } from '../test-utils/appFactory';
 * import request from 'supertest';
 * 
 * describe('My Tests', () => {
 *   let app: Express;
 *   
 *   beforeEach(() => {
 *     app = createTestApp((app) => {
 *       app.get('/custom-endpoint', (_req, res) => {
 *         res.json({ data: 'test' });
 *       });
 *     });
 *   });
 *   
 *   it('should work', async () => {
 *     const response = await request(app).get('/custom-endpoint');
 *     expect(response.status).toBe(200);
 *   });
 * });
 * ```
 */
export function createTestApp(setupCallback?: (app: Express) => void): Express {
  const app = express();

  // Standard middleware
  app.use(express.json());
  app.use(cookieParser());

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // API routes
  app.use('/api/auth', authRoutes);
  app.use('/api/patients', patientRoutes);
  app.use('/api/medical-history', medicalHistoryRoutes);
  app.use('/api/dashboard', dashboardRoutes);

  // Allow test files to add custom routes/middleware
  if (setupCallback) {
    setupCallback(app);
  }

  // Error handler (must be last)
  app.use(errorHandler as any);

  return app;
}

/**
 * Creates a minimal test app with only basic middleware
 * Useful for unit testing specific middleware or handlers
 * 
 * @returns Express app with minimal configuration
 */
export function createMinimalApp(): Express {
  const app = express();
  app.use(express.json());
  app.use(errorHandler as any);
  return app;
}
