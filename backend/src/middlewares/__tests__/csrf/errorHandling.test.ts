import request from 'supertest';
import express, {
  Request,
  Response as ExpressResponse,
} from 'express';
import { createCsrfMiddleware } from '../../csrfMiddleware';
import cookieParser from 'cookie-parser';
import errorHandler from '../../errorHandler';

describe('CSRF Middleware - Error Handling', () => {
  let app: express.Express;

  beforeEach(() => {
    process.env.CSRF_SECRET = 'test-secret-1234567890';
    process.env.NODE_ENV = 'test';
    process.env.PROXY_SECURE = 'true';
    process.env.COOKIE_HTTPONLY = 'true';
    process.env.COOKIE_SAMESITE = 'lax';

    app = express();
    app.use(express.json());
    app.use(cookieParser());
    const { doubleCsrfProtection } = createCsrfMiddleware();
    app.use(doubleCsrfProtection);
    app.use(errorHandler);

    app.post('/test-post', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('POST OK');
    });
  });

  afterEach(() => {
    delete process.env.CSRF_SECRET;
    jest.restoreAllMocks();
    jest.clearAllMocks();
  });

  it('should throw error when CSRF_SECRET is missing', () => {
    const originalSecret = process.env.CSRF_SECRET;
    delete process.env.CSRF_SECRET;

    expect(() => createCsrfMiddleware()).toThrow('CSRF secret not configured');

    process.env.CSRF_SECRET = originalSecret;
  });

  it('should handle invalid token format', async () => {
    const response = await request(app)
      .post('/test-post')
      .set('x-csrf-token', 'invalid-token-format');

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('CSRF_TOKEN_MISSING_OR_INVALID');
  });
});
