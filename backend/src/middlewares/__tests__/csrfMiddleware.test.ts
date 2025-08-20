import request, { agent, Response } from 'supertest';
import express, {
  Request,
  Response as ExpressResponse,
} from 'express';
import { createCsrfMiddleware, getSessionIdentifier } from '../csrfMiddleware';
import cookieParser from 'cookie-parser';
import { doubleCsrf } from 'csrf-csrf';
import errorHandler from '../errorHandler';

const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();

describe('CSRF Middleware', () => {
  let app: express.Express;
  const CSRF_SECRET = 'test-secret-1234567890';

  beforeEach(() => {
    process.env.CSRF_SECRET = CSRF_SECRET;
    process.env.NODE_ENV = 'test';

    app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use(doubleCsrfProtection);
    app.use(errorHandler);

    app.get('/test-get', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('GET OK');
      return;
    });
    app.post('/test-post', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('POST OK');
      return;
    });
    app.put('/test-put', (_req: Request, res: ExpressResponse) => {
      res.status(200).send('PUT OK');
    });
    app.delete(
      '/test-delete',
      (_req: Request, res: ExpressResponse) => {
        res.status(200).send('DELETE OK');
      }
    );

    app.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = generateCsrfToken(req, res);
        res.status(200).json({ token });
      });
  });

  afterEach(() => {
    delete process.env.CSRF_SECRET;
  });

  const getCsrfToken = (res: Response): string | undefined => {
    const cookies = res.headers['set-cookie'];
    if (!cookies) return undefined;

    const cookieArray = Array.isArray(cookies) ? cookies : [cookies];
    const csrfCookie = cookieArray.find(c => c.includes('csrfToken='));
    if (!csrfCookie) return undefined;
    
    return csrfCookie
      .split(';')[0]
      .split('=')[1];
  };

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
      
      const setCookieHeader = getResponse.headers['set-cookie'];
      expect(setCookieHeader).toBeDefined();
      const cookieArray = Array.isArray(setCookieHeader)
        ? setCookieHeader
        : [setCookieHeader || ''];
      expect(cookieArray.join('')).toMatch(/csrfToken=[^;]+/);
      
      const token = getCsrfToken(getResponse);
      const response = await testAgent
        .post('/test-post')
        .set('x-csrf-token', token || '')
        .send({});

      expect(response.status).toBe(200);
      expect(response.text).toBe('POST OK');
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
    it('should use req.ip when available', () => {
      const req = {
        ip: '192.168.1.1',
        headers: {}
      } as Request;
      
      expect(getSessionIdentifier(req)).toBe('192.168.1.1');
    });

    it('should handle IPv6 address in req.ip', () => {
      const req = {
        ip: '2001:db8::1',
        headers: {}
      } as Request;
      
      expect(getSessionIdentifier(req)).toBe('2001:db8::1');
    });

    it('should use first X-Forwarded-For array element', () => {
      const req = {
        ip: undefined,
        headers: {
          'x-forwarded-for': ['192.168.1.100', '10.0.0.1']
        }
      } as unknown as Request;
      
      expect(getSessionIdentifier(req)).toBe('192.168.1.100');
    });

    it('should handle IPv6 address in X-Forwarded-For array', () => {
      const req = {
        ip: undefined,
        headers: {
          'x-forwarded-for': ['2001:db8::1', '2001:db8::2']
        }
      } as unknown as Request;
      
      expect(getSessionIdentifier(req)).toBe('2001:db8::1');
    });

    it('should use X-Forwarded-For string value', () => {
      const req = {
        ip: undefined,
        headers: {
          'x-forwarded-for': '192.168.1.100'
        }
      } as unknown as Request;
      
      expect(getSessionIdentifier(req)).toBe('192.168.1.100');
    });

    it('should handle IPv6 address in X-Forwarded-For string', () => {
      const req = {
        ip: undefined,
        headers: {
          'x-forwarded-for': '2001:db8::1'
        }
      } as unknown as Request;
      
      expect(getSessionIdentifier(req)).toBe('2001:db8::1');
    });

    it('should use default when no IP or headers', () => {
      const req = {
        ip: undefined,
        headers: {}
      } as Request;
      
      expect(getSessionIdentifier(req)).toBe('default-session');
    });

    it('should use req.cookies.session when available', () => {
      const req = {
        cookies: {
          session: 'test-session-id'
        },
        ip: '192.168.1.1',
        headers: {}
      } as unknown as Request;
      
      expect(getSessionIdentifier(req)).toBe('test-session-id');
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

  describe('Cookie Security Settings', () => {
    const originalEnv = process.env.NODE_ENV;

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it('should set Secure flag in production', async () => {
      process.env.NODE_ENV = 'production';
      
      const { doubleCsrfProtection: prodCsrfProtection, generateCsrfToken: prodGenerateToken } = createCsrfMiddleware();
      
      const prodApp = express();
      prodApp.use(express.json());
      prodApp.use(cookieParser());
      prodApp.use(prodCsrfProtection);

      prodApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = prodGenerateToken(req, res);
        res.status(200).json({ token });
      });

      const testAgent = agent(prodApp);
      const response = await testAgent.get('/csrf-token');
      const cookies = response.headers['set-cookie'];
      const cookieHeader = Array.isArray(cookies)
        ? cookies.join(';')
        : cookies || '';

      expect(cookieHeader).toContain('Secure');
      expect(cookieHeader).toContain('HttpOnly');
      expect(cookieHeader).toContain('SameSite=Strict');
    });

    it('should not set Secure flag in non-production', async () => {
      process.env.NODE_ENV = 'development';
      
      const { doubleCsrfProtection: devCsrfProtection, generateCsrfToken: devGenerateToken } = createCsrfMiddleware();
      
      const devApp = express();
      devApp.use(express.json());
      devApp.use(cookieParser());
      devApp.use(devCsrfProtection);

      devApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = devGenerateToken(req, res);
        res.status(200).json({ token });
      });

      const testAgent = agent(devApp);
      const response = await testAgent.get('/csrf-token');
      const cookies = response.headers['set-cookie'];
      const cookieHeader = Array.isArray(cookies)
        ? cookies.join(';')
        : cookies || '';
      
      expect(cookieHeader).not.toContain('Secure');
      expect(cookieHeader).toContain('HttpOnly');
      expect(cookieHeader).toContain('SameSite=Strict');
    });

    it('should set HttpOnly flag in all environments', async () => {
      const { doubleCsrfProtection: devCsrfProtection, generateCsrfToken: devGenerateToken } = createCsrfMiddleware();
      
      const devApp = express();
      devApp.use(express.json());
      devApp.use(cookieParser());
      devApp.use(devCsrfProtection);

      devApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = devGenerateToken(req, res);
        res.status(200).json({ token });
      });

      const testAgent = agent(devApp);
      const response = await testAgent.get('/csrf-token');
      const cookies = response.headers['set-cookie'];
      const cookieHeader = Array.isArray(cookies)
        ? cookies.join(';')
        : cookies || '';
      
      expect(cookieHeader).toContain('HttpOnly');
    });

    it('should set SameSite=Strict in all environments', async () => {
      const { doubleCsrfProtection: devCsrfProtection, generateCsrfToken: devGenerateToken } = createCsrfMiddleware();
      
      const devApp = express();
      devApp.use(express.json());
      devApp.use(cookieParser());
      devApp.use(devCsrfProtection);

      devApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = devGenerateToken(req, res);
        res.status(200).json({ token });
      });

      const testAgent = agent(devApp);
      const response = await testAgent.get('/csrf-token');
      const cookies = response.headers['set-cookie'];
      const cookieHeader = Array.isArray(cookies)
        ? cookies.join(';')
        : cookies || '';
      
      expect(cookieHeader).toContain('SameSite=Strict');
    });

    it('should set correct maxAge expiration', async () => {
      const testAgent = agent(app);
      const response = await testAgent.get('/csrf-token');
      const cookies = response.headers['set-cookie'];
      const cookieHeader = Array.isArray(cookies)
        ? cookies.join(';')
        : cookies || '';
      
      expect(cookieHeader).toContain('Max-Age=3600');
    });
  });

  describe('Error Handling', () => {
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

  describe('HTTP Method Exemptions', () => {
    it('should not require CSRF token for GET requests', async () => {
      const response = await request(app).get('/test-get');
      expect(response.status).toBe(200);
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
          secure: false, // because NODE_ENV is test
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

  describe('HTTP Method Exemptions', () => {
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
  });
});
