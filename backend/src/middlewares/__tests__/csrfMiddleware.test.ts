import request, { agent } from 'supertest';
import express, {
  Request,
  Response as ExpressResponse,
} from 'express';
import { createCsrfMiddleware, getSessionIdentifier } from '../csrfMiddleware';
import cookieParser from 'cookie-parser';
import { doubleCsrf } from 'csrf-csrf';
import errorHandler from '../errorHandler';
import logger from '../../utils/logger';

const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();

describe('CSRF Middleware', () => {
  let app: express.Express;
  const CSRF_SECRET = 'test-secret-1234567890';

  beforeEach(() => {
    process.env.CSRF_SECRET = CSRF_SECRET;
    process.env.NODE_ENV = 'test';
    process.env.PROXY_SECURE = 'true'; // Ensure secure cookies in tests
    process.env.COOKIE_HTTPONLY = 'true'; // Prevent warnings
    process.env.COOKIE_SAMESITE = 'lax'; // Prevent warnings

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
    // Allow Jest to clean up
    jest.restoreAllMocks();
    jest.clearAllMocks();
  });

  // const getCsrfToken = (res: Response): string | undefined => {
  //   const cookies = res.headers['set-cookie'];
  //   if (!cookies) return undefined;

  //   const cookieArray = Array.isArray(cookies) ? cookies : [cookies];
  //   const csrfCookie = cookieArray.find(c => c.includes('csrfToken='));
  //   if (!csrfCookie) return undefined;
    
  //   return csrfCookie
  //     .split(';')[0]
  //     .split('=')[1];
  // };

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
      // UUID regex pattern
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

  describe('Cookie Security Settings', () => {
    const originalEnv = process.env.NODE_ENV;
    const originalSameSite = process.env.COOKIE_SAMESITE;

    beforeEach(() => {
      // Clear COOKIE_SAMESITE to test defaults
      delete process.env.COOKIE_SAMESITE;
    });

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
      if (originalSameSite !== undefined) {
        process.env.COOKIE_SAMESITE = originalSameSite;
      } else {
        delete process.env.COOKIE_SAMESITE;
      }
    });

    it('should set Secure flag in production', async () => {
      process.env.NODE_ENV = 'production';
      process.env.COOKIE_DOMAIN = 'example.com';
      // Explicitly set COOKIE_SAMESITE to strict for this test
      process.env.COOKIE_SAMESITE = 'strict';
      
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
      // Explicitly set COOKIE_SAMESITE to strict for this test
      process.env.COOKIE_SAMESITE = 'strict';
      
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

    it('should set HttpOnly flag based on COOKIE_HTTPONLY environment variable', async () => {
      // Test when COOKIE_HTTPONLY=true
      process.env.COOKIE_HTTPONLY = 'true';
      const { doubleCsrfProtection: trueCsrfProtection, generateCsrfToken: trueGenerateToken } = createCsrfMiddleware();
      
      const trueApp = express();
      trueApp.use(express.json());
      trueApp.use(cookieParser());
      trueApp.use(trueCsrfProtection);

      trueApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = trueGenerateToken(req, res);
        res.status(200).json({ token });
      });

      const trueAgent = agent(trueApp);
      const trueResponse = await trueAgent.get('/csrf-token');
      const trueCookies = trueResponse.headers['set-cookie'];
      const trueCookieHeader = Array.isArray(trueCookies)
        ? trueCookies.join(';')
        : trueCookies || '';
      expect(trueCookieHeader).toContain('HttpOnly');

      // Test when COOKIE_HTTPONLY=false
      process.env.COOKIE_HTTPONLY = 'false';
      const { doubleCsrfProtection: falseCsrfProtection, generateCsrfToken: falseGenerateToken } = createCsrfMiddleware();
      
      const falseApp = express();
      falseApp.use(express.json());
      falseApp.use(cookieParser());
      falseApp.use(falseCsrfProtection);

      falseApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = falseGenerateToken(req, res);
        res.status(200).json({ token });
      });

      const falseAgent = agent(falseApp);
      const falseResponse = await falseAgent.get('/csrf-token');
      const falseCookies = falseResponse.headers['set-cookie'];
      const falseCookieHeader = Array.isArray(falseCookies)
        ? falseCookies.join(';')
        : falseCookies || '';
      expect(falseCookieHeader).not.toContain('HttpOnly');
    });

    it('should set SameSite attribute based on COOKIE_SAMESITE environment variable', async () => {
      // Test development environment with COOKIE_SAMESITE=none
      process.env.NODE_ENV = 'development';
      process.env.COOKIE_SAMESITE = 'none';
      const { doubleCsrfProtection: devCsrfProtection1, generateCsrfToken: devGenerateToken1 } = createCsrfMiddleware();
      
      const devApp1 = express();
      devApp1.use(express.json());
      devApp1.use(cookieParser());
      devApp1.use(devCsrfProtection1);

      devApp1.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = devGenerateToken1(req, res);
        res.status(200).json({ token });
      });

      const testAgent1 = agent(devApp1);
      const response1 = await testAgent1.get('/csrf-token');
      const cookies1 = response1.headers['set-cookie'];
      const cookieHeader1 = Array.isArray(cookies1)
        ? cookies1.join(';')
        : cookies1 || '';
      expect(cookieHeader1).toContain('SameSite=None');
      // In development, Secure flag should not be present
      expect(cookieHeader1).not.toContain('Secure');

      // Test production environment with COOKIE_SAMESITE=lax
      process.env.NODE_ENV = 'production';
      process.env.COOKIE_SAMESITE = 'lax';
      const { doubleCsrfProtection: prodCsrfProtection, generateCsrfToken: prodGenerateToken } = createCsrfMiddleware();
      
      const prodApp = express();
      prodApp.use(express.json());
      prodApp.use(cookieParser());
      prodApp.use(prodCsrfProtection);

      prodApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = prodGenerateToken(req, res);
        res.status(200).json({ token });
      });

      const testAgentProd = agent(prodApp);
      const responseProd = await testAgentProd.get('/csrf-token');
      const cookiesProd = responseProd.headers['set-cookie'];
      const cookieHeaderProd = Array.isArray(cookiesProd)
        ? cookiesProd.join(';')
        : cookiesProd || '';
      expect(cookieHeaderProd).toContain('SameSite=Lax');

      // Test without COOKIE_SAMESITE in development -> defaults to strict
      delete process.env.COOKIE_SAMESITE;
      process.env.NODE_ENV = 'development';
      const { doubleCsrfProtection: devCsrfProtection2, generateCsrfToken: devGenerateToken2 } = createCsrfMiddleware();
      
      const devApp2 = express();
      devApp2.use(express.json());
      devApp2.use(cookieParser());
      devApp2.use(devCsrfProtection2);

      devApp2.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = devGenerateToken2(req, res);
        res.status(200).json({ token });
      });

      const testAgent2 = agent(devApp2);
      const response2 = await testAgent2.get('/csrf-token');
      const cookies2 = response2.headers['set-cookie'];
      const cookieHeader2 = Array.isArray(cookies2)
        ? cookies2.join(';')
        : cookies2 || '';
      expect(cookieHeader2).toContain('SameSite=Strict');
      // In development, Secure flag should not be present
      expect(cookieHeader2).not.toContain('Secure');

      // Test with COOKIE_SAMESITE=lax in production
      process.env.NODE_ENV = 'production';
      process.env.COOKIE_SAMESITE = 'lax';
      const { doubleCsrfProtection: prodCsrfProtection2, generateCsrfToken: prodGenerateToken2 } = createCsrfMiddleware();
      
      const prodApp2 = express();
      prodApp2.use(express.json());
      prodApp2.use(cookieParser());
      prodApp2.use(prodCsrfProtection2);

      prodApp2.get('/csrf-token', (req: Request, res: ExpressResponse) => {
        const token = prodGenerateToken2(req, res);
        res.status(200).json({ token });
      });

      const testAgentProd2 = agent(prodApp2);
      const responseProd2 = await testAgentProd2.get('/csrf-token');
      const cookiesProd2 = responseProd2.headers['set-cookie'];
      const cookieHeaderProd2 = Array.isArray(cookiesProd2)
        ? cookiesProd2.join(';')
        : cookiesProd2 || '';
      expect(cookieHeaderProd2).toContain('SameSite=Lax');
      // In production, Secure flag should be present
      expect(cookieHeaderProd2).toContain('Secure');
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
