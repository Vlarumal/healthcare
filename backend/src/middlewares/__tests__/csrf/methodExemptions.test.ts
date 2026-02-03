import request from 'supertest';
import express, {
  Request,
  Response as ExpressResponse,
} from 'express';
import { createCsrfMiddleware } from '../../csrfMiddleware';
import cookieParser from 'cookie-parser';
import { doubleCsrf } from 'csrf-csrf';
import errorHandler from '../../errorHandler';

describe('CSRF Middleware - HTTP Method Exemptions', () => {
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

    app.get('/test-get', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('GET OK');
    });
    app.head('/test-get', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('HEAD OK');
    });
    app.options('/test-get', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('OPTIONS OK');
    });
    app.post('/test-post', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('POST OK');
    });
    app.put('/test-put', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('PUT OK');
    });
    app.delete('/test-delete', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('DELETE OK');
    });
  });

  afterEach(() => {
    delete process.env.CSRF_SECRET;
    jest.restoreAllMocks();
    jest.clearAllMocks();
  });

  it('should not require CSRF token for GET requests', async () => {
    const response = await request(app).get('/test-get');
    expect(response.status).toBe(200);
  });

  it('should not require CSRF token for HEAD requests', async () => {
    const response = await request(app).head('/test-get');
    expect(response.status).toBe(200);
  });

  it('should not require CSRF token for OPTIONS requests', async () => {
    const response = await request(app).options('/test-get');
    expect(response.status).toBe(200);
  });

  it('should require CSRF token for POST requests', async () => {
    const response = await request(app).post('/test-post');
    expect(response.status).toBe(403);
  });

  it('should require CSRF token for PUT requests', async () => {
    const response = await request(app).put('/test-put');
    expect(response.status).toBe(403);
  });

  it('should require CSRF token for DELETE requests', async () => {
    const response = await request(app).delete('/test-delete');
    expect(response.status).toBe(403);
  });

  it('should handle invalid session identifier', async () => {
    const doubleCsrfOptions = {
      getSecret: () => process.env.CSRF_SECRET!,
      getSessionIdentifier: () => { throw new Error('Invalid session identifier'); },
      cookieName: 'csrfToken',
      size: 64,
      cookieOptions: {
        httpOnly: true,
        sameSite: 'strict' as const,
        path: '/',
        secure: false,
        maxAge: 3600,
      },
      errorConfig: {
        code: 'CSRF_TOKEN_MISSING_OR_INVALID',
        message: 'CSRF token missing or invalid'
      }
    };

    const { doubleCsrfProtection } = doubleCsrf(doubleCsrfOptions);

    const testApp = express();
    testApp.use(express.json());
    testApp.use(cookieParser());
    testApp.use(doubleCsrfProtection);
    testApp.use(errorHandler);

    testApp.post('/test-post', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('POST OK');
    });

    const response = await request(testApp).post('/test-post');
    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        status: 403,
        code: 'CSRF_TOKEN_MISSING_OR_INVALID',
        message: 'CSRF token missing or invalid'
      }
    });
  });
});
