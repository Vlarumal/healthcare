import logger from './utils/logger';

export const JWT_SECRET = process.env.JWT_SECRET || 'default-secret';
export const REFRESH_TOKEN_SECRET =
  process.env.REFRESH_TOKEN_SECRET || 'default-refresh-secret';

export const ACCESS_TOKEN_EXPIRES_IN_MINUTES = parseInt(
  process.env.ACCESS_TOKEN_EXPIRES_IN || '1440',
  10,
); // 24 hours
export const REFRESH_TOKEN_EXPIRES_IN_DAYS = parseInt(
  process.env.REFRESH_TOKEN_EXPIRES_IN || '7',
  10,
);

export const ACCESS_TOKEN_EXPIRES_IN_MS =
  ACCESS_TOKEN_EXPIRES_IN_MINUTES * 60 * 1000;
export const REFRESH_TOKEN_EXPIRES_IN_MS =
  REFRESH_TOKEN_EXPIRES_IN_DAYS * 24 * 60 * 60 * 1000;

export const ACCESS_TOKEN_EXPIRES_IN = `${ACCESS_TOKEN_EXPIRES_IN_MINUTES}m`;
export const REFRESH_TOKEN_EXPIRES_IN = `${REFRESH_TOKEN_EXPIRES_IN_DAYS}d`;

export const cookieDomain = process.env.COOKIE_DOMAIN || '';
export const isProduction = process.env.NODE_ENV === 'production';
export const CSRF_SECRET = process.env.CSRF_SECRET || '';

export let sameSite: 'lax' | 'strict' | 'none' | boolean | undefined;
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

export let httpOnly = true;
if (process.env.COOKIE_HTTPONLY !== undefined) {
  httpOnly = process.env.COOKIE_HTTPONLY.toLowerCase() === 'true';
} else {
  logger.warn('COOKIE_HTTPONLY not set, using default httpOnly=true');
}

export const getCookieDomain = (host: string): string | undefined => {
  const hostname = host.split(':')[0];
  
  // localhost - omit Domain attribute for host-only cookie
  if (hostname === 'localhost' || hostname === '127.0.0.1')
    return undefined;

  // Render.com auto-generated subdomains - use host-only cookie (omit Domain)
  // This is more secure and avoids RFC 6265 public suffix issues
  if (hostname.endsWith('.onrender.com')) {
    return '.onrender.com';  
  }

  // Custom domains - use exact hostname without leading dot
  // This creates a host-only cookie for the specific subdomain
  if (hostname.includes('.')) {
    return hostname;
  }

  // Default: host-only cookie (omit Domain attribute)
  return undefined;
};
