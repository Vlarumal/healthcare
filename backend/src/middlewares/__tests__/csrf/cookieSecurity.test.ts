import { agent } from 'supertest';
import express, {
  Request,
  Response as ExpressResponse,
} from 'express';
import { createCsrfMiddleware } from '../../csrfMiddleware';
import cookieParser from 'cookie-parser';

describe('CSRF Middleware - Cookie Security Settings', () => {
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
    process.env.COOKIE_SAMESITE = 'strict';

    const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();

    const prodApp = express();
    prodApp.use(express.json());
    prodApp.use(cookieParser());
    prodApp.use(doubleCsrfProtection);

    prodApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
      const token = generateCsrfToken(req, res);
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
    process.env.COOKIE_SAMESITE = 'strict';

    const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();

    const devApp = express();
    devApp.use(express.json());
    devApp.use(cookieParser());
    devApp.use(doubleCsrfProtection);

    devApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
      const token = generateCsrfToken(req, res);
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
    const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();

    const trueApp = express();
    trueApp.use(express.json());
    trueApp.use(cookieParser());
    trueApp.use(doubleCsrfProtection);

    trueApp.get('/csrf-token', (req: Request, res: ExpressResponse) => {
      const token = generateCsrfToken(req, res);
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
    const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();

    const devApp1 = express();
    devApp1.use(express.json());
    devApp1.use(cookieParser());
    devApp1.use(doubleCsrfProtection);

    devApp1.get('/csrf-token', (req: Request, res: ExpressResponse) => {
      const token = generateCsrfToken(req, res);
      res.status(200).json({ token });
    });

    const testAgent1 = agent(devApp1);
    const response1 = await testAgent1.get('/csrf-token');
    const cookies1 = response1.headers['set-cookie'];
    const cookieHeader1 = Array.isArray(cookies1)
      ? cookies1.join(';')
      : cookies1 || '';
    expect(cookieHeader1).toContain('SameSite=None');
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
    expect(cookieHeaderProd2).toContain('Secure');
  });

  it('should set correct maxAge expiration', async () => {
    const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();

    const app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use(doubleCsrfProtection);

    app.get('/csrf-token', (req: Request, res: ExpressResponse) => {
      const token = generateCsrfToken(req, res);
      res.status(200).json({ token });
    });

    const testAgent = agent(app);
    const response = await testAgent.get('/csrf-token');
    const cookies = response.headers['set-cookie'];
    const cookieHeader = Array.isArray(cookies)
      ? cookies.join(';')
      : cookies || '';

    expect(cookieHeader).toContain('Max-Age=3600');
  });
});
