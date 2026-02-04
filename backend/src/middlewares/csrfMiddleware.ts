import dotenv from 'dotenv';

import {
  Request,
} from 'express';
import { doubleCsrf } from 'csrf-csrf';
import logger from '../utils/logger';
import {
  CSRF_SECRET,
  getCookieDomain,
} from '../config';
import { InternalServerError } from '../errors/httpErrors';
import path from 'path';

// Load .env from the project root (works for both src/ and build/ directories)
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

// Does it require a session cookie like express-session?
// No. The library is designed to work without sessions. The fallback mechanism is intentional.
// What happens when no session cookie exists?
// Uses IP+User-Agent hash fallback. This is the expected behavior for stateless CSRF protection.
export const getSessionIdentifier = (req: Request): string => {
  // Check for session cookie first
  if (req.cookies?.session) {
    return req.cookies.session;
  }

  if (req.session && req.session.id) {
    return req.session.id;
  }

  if (req.user && (req.user as any).id) {
    return (req.user as any).id;
  }

  // Use optional chaining to handle cases where socket or headers might be undefined (e.g., in tests)
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const userAgent = req.headers?.['user-agent'] || '';

  // Generate a UUID-based identifier from IP and user agent for uniqueness
  const hash = require('crypto')
    .createHash('sha256')
    .update(`${ip}-${userAgent}`)
    .digest('hex');
  // Convert to UUID-like format (8-4-4-4-12)
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-8${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
};

export const createCsrfMiddleware = () => {
  if (!process.env.CSRF_SECRET) {
    throw new Error('CSRF secret not configured');
  }

  if (!process.env.CSRF_SECRET || process.env.CSRF_SECRET === '') {
    logger.error(
      'CSRF_SECRET environment variable is not set or is empty',
    );
    throw new InternalServerError(
      'Internal server error',
      'SERVER_ERROR',
    );
  }

  let sameSite: 'lax' | 'strict' | 'none' | boolean | undefined;
  if (process.env.COOKIE_SAMESITE) {
    const validValues = ['lax', 'strict', 'none', 'true', 'false'];
    if (validValues.includes(process.env.COOKIE_SAMESITE)) {
      if (process.env.COOKIE_SAMESITE === 'true') {
        sameSite = true;
      } else if (process.env.COOKIE_SAMESITE === 'false') {
        sameSite = false;
      } else {
        sameSite = process.env.COOKIE_SAMESITE as
          | 'lax'
          | 'strict'
          | 'none';
      }
    } else {
      logger.warn(
        `COOKIE_SAMESITE value: ${process.env.COOKIE_SAMESITE}. Using 'none' in production for render.com, 'strict' in development.`,
      );
    }
  }

  if (sameSite === undefined) {
    sameSite =
      process.env.NODE_ENV === 'production' ? 'none' : 'strict';
  }

  let httpOnly = true;
  if (process.env.COOKIE_HTTPONLY !== undefined) {
    httpOnly = process.env.COOKIE_HTTPONLY.toLowerCase() === 'true';
    logger.info(
      `COOKIE_HTTPONLY=${process.env.COOKIE_HTTPONLY} -> httpOnly=${httpOnly}`,
    );
  } else {
    logger.warn(
      'COOKIE_HTTPONLY not set, using default httpOnly=true',
    );
  }
  const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
    getSecret: () => CSRF_SECRET,
    getSessionIdentifier,
    cookieName: 'csrfToken',
    cookieOptions: ((req: Request) => ({
      secure: process.env.NODE_ENV === 'production',
      sameSite,
      httpOnly,
      maxAge: 3600000,
      path: '/',
      ...(getCookieDomain(req.hostname) && {
        domain: getCookieDomain(req.hostname),
      }),
    })) as any,
    size: 64,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  });
  return {
    doubleCsrfProtection,
    generateCsrfToken,
  };
};
