import { Request } from 'express';
import { doubleCsrf } from 'csrf-csrf';
import dotenv from 'dotenv';

dotenv.config();

const getSessionIdentifier = (req: Request): string => {
  if (req.cookies && req.cookies.session) {
    return req.cookies.session;
  }
  
  if (req.ip) return req.ip;
  const forwarded = req.headers['x-forwarded-for'];
  if (Array.isArray(forwarded)) {
    return forwarded[0];
  }
  return forwarded || 'default';
};

export const createCsrfMiddleware = () => {
  if (!process.env.CSRF_SECRET) {
    throw new Error('CSRF secret not configured');
  }

  const cookieDomain = process.env.NODE_ENV === 'production' && process.env.COOKIE_DOMAIN
    ? process.env.COOKIE_DOMAIN
    : undefined;

  const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
    getSecret: () => process.env.CSRF_SECRET!,
    getSessionIdentifier,
    cookieName: 'csrfToken',
    cookieOptions: {
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      httpOnly: true,
      domain: cookieDomain,
      maxAge: 3600000, // 1 hour expiration
    },
    size: 64,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
    errorConfig: {
      code: 'CSRF_TOKEN_MISSING_OR_INVALID',
      message: 'CSRF token missing or invalid'
    }
  });

  return { doubleCsrfProtection, generateCsrfToken };
};

const { doubleCsrfProtection, generateCsrfToken } = createCsrfMiddleware();
export {
  doubleCsrfProtection,
  generateCsrfToken,
  getSessionIdentifier
};
