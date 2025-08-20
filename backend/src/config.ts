export const JWT_SECRET = process.env.JWT_SECRET || 'default-secret';
export const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'default-refresh-secret';

export const ACCESS_TOKEN_EXPIRES_IN_MINUTES = parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN || '1440', 10); // 24 hours
export const REFRESH_TOKEN_EXPIRES_IN_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN || '7', 10);

export const ACCESS_TOKEN_EXPIRES_IN_MS = ACCESS_TOKEN_EXPIRES_IN_MINUTES * 60 * 1000;
export const REFRESH_TOKEN_EXPIRES_IN_MS = REFRESH_TOKEN_EXPIRES_IN_DAYS * 24 * 60 * 60 * 1000;

export const ACCESS_TOKEN_EXPIRES_IN = `${ACCESS_TOKEN_EXPIRES_IN_MINUTES}m`;
export const REFRESH_TOKEN_EXPIRES_IN = `${REFRESH_TOKEN_EXPIRES_IN_DAYS}d`;

export const cookieDomain = process.env.COOKIE_DOMAIN || '';
export const isProduction = process.env.NODE_ENV === 'production';
export const CSRF_SECRET = process.env.CSRF_SECRET || '';