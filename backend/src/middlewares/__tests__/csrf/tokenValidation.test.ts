import request, { agent } from 'supertest';
import express, {
  Request,
  Response as ExpressResponse,
} from 'express';
import { createCsrfMiddleware, getSessionIdentifier } from '../../csrfMiddleware';
import cookieParser from 'cookie-parser';
import errorHandler from '../../errorHandler';
import logger from '../../../utils/logger';

const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();

describe('CSRF Middleware - Token Validation', () => {
  let app: express.Express;
  const CSRF_SECRET = 'test-secret-1234567890';

  beforeEach(() => {
    process.env.CSRF_SECRET = CSRF_SECRET;
    process.env.NODE_ENV = 'test';
    process.env.PROXY_SECURE = 'true';
    process.env.COOKIE_HTTPONLY = 'true';
    process.env.COOKIE_SAMESITE = 'lax';

    app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use(doubleCsrfProtection);
    app.use(errorHandler);

    app.get('/test-get', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('GET OK');
    });
    app.post('/test-post', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('POST OK');
    });

    app.get('/csrf-token', (req: Request, res: ExpressResponse) => {
      const token = generateCsrfToken(req, res);
      res.status(200).json({ token });
    });
  });

  afterEach(() => {
    delete process.env.CSRF_SECRET;
    jest.restoreAllMocks();
    jest.clearAllMocks();
  });

  describe('Token Validation Logic', () => {
    it('should reject POST requests without CSRF token', async () => {
      const response = await request(app).post('/test-post').send({});

      expect(response.status).toBe(403);
      expect(response.body).toEqual({
        error: {
          status: 403,
          code: 'CSRF_TOKEN_MISSING_OR_INVALID',
          message: 'CSRF token missing or invalid'
        }
      });
    });

    it('should accept valid CSRF token in header', async () => {
      const testAgent = agent(app);

      const getResponse = await testAgent.get('/csrf-token');
      const token = getResponse.body.token;

      const response = await testAgent
        .post('/test-post')
        .set('x-csrf-token', token || '')
        .send({});

      expect(response.status).toBe(200);
      expect(response.text).toBe('POST OK');
    });

    it('should log HttpOnly value when COOKIE_HTTPONLY is set', async () => {
      const logSpy = jest.spyOn(logger, 'info');
      process.env.COOKIE_HTTPONLY = 'true';
      createCsrfMiddleware();
      expect(logSpy).toHaveBeenCalledWith('COOKIE_HTTPONLY=true -> httpOnly=true');
      logSpy.mockRestore();
    });

    it('should log warning when COOKIE_HTTPONLY is not set', async () => {
      const warnSpy = jest.spyOn(logger, 'warn');
      delete process.env.COOKIE_HTTPONLY;
      createCsrfMiddleware();
      expect(warnSpy).toHaveBeenCalledWith('COOKIE_HTTPONLY not set, using default httpOnly=true');
      warnSpy.mockRestore();
    });

    it('should log warning when COOKIE_SAMESITE has invalid value', async () => {
      const warnSpy = jest.spyOn(logger, 'warn');
      process.env.COOKIE_SAMESITE = 'invalid';
      createCsrfMiddleware();
      expect(warnSpy).toHaveBeenCalledWith(
        `COOKIE_SAMESITE value: ${process.env.COOKIE_SAMESITE}. Using 'none' in production for render.com, 'strict' in development.`
      );
      warnSpy.mockRestore();
    });

    it('should reject invalid CSRF token', async () => {
      const response = await request(app)
        .post('/test-post')
        .set('x-csrf-token', 'invalid-token')
        .send({});

      expect(response.status).toBe(403);
    });

    it('should reject requests with missing token in header', async () => {
      const testAgent = agent(app);
      await testAgent.get('/test-get');
      const response = await testAgent
        .post('/test-post')
        .set('x-csrf-token', '')
        .send({});
      expect(response.status).toBe(403);
    });
  });

  describe('getSessionIdentifier() Unit Tests', () => {
    it('should use req.cookies.session when available', () => {
      const req = {
        cookies: {
          session: 'test-session-id'
        }
      } as unknown as Request;

      expect(getSessionIdentifier(req)).toBe('test-session-id');
    });

    it('should generate a UUID when no session cookie exists', () => {
      const req = {
        cookies: {}
      } as unknown as Request;

      const sessionId = getSessionIdentifier(req);
      const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(sessionId).toMatch(uuidPattern);
    });
  });

  describe('X-Forwarded-For Header Handling', () => {
    it('should handle comma-separated multiple IPs in X-Forwarded-For', async () => {
      const response = await request(app)
        .get('/test-get')
        .set('X-Forwarded-For', '192.168.1.100, 10.0.0.1');

      expect(response.status).toBe(200);
    });

    it('should handle single string IP in X-Forwarded-For', async () => {
      const response = await request(app)
        .get('/test-get')
        .set('X-Forwarded-For', '192.168.1.100');

      expect(response.status).toBe(200);
    });

    it('should handle empty X-Forwarded-For header', async () => {
      const response = await request(app)
        .get('/test-get')
        .set('X-Forwarded-For', '');

      expect(response.status).toBe(200);
    });

    it('should handle malformed X-Forwarded-For header', async () => {
      const response = await request(app)
        .get('/test-get')
        .set('X-Forwarded-For', 'invalid-ip-address');

      expect(response.status).toBe(200);
    });

    it('should use IP address when available', async () => {
      const response = await request(app)
        .get('/test-get')
        .set('X-Forwarded-For', '192.168.1.100')
        .set('x-real-ip', '10.0.0.1');

      expect(response.status).toBe(200);
    });
  });
});
