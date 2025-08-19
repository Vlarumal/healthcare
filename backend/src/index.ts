import express, { Application, Response } from 'express';
import cors from 'cors';
import { QueryRunner } from 'typeorm';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import {
  doubleCsrfProtection,
  generateCsrfToken,
} from './middlewares/csrfMiddleware';
import patientRoutes from './routes/patientRoutes';
import medicalHistoryRoutes from './routes/medicalHistoryRoutes';
import errorHandler from './middlewares/errorHandler';
import { AppDataSource } from './data-source';
import authRoutes from './routes/authRoutes';
import dashboardRoutes from './routes/dashboardRoutes';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

declare global {
  namespace Express {
    interface Request {
      queryRunner?: QueryRunner;
    }
  }
}

dotenv.config();

const app: Application = express();
app.use(express.json());

const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',')
  : ['http://localhost:5173', 'http://localhost:3001', 'https://healthcare-2rmw.onrender.com'];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`Not allowed by CORS: ${origin}`));
      }
    },
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    exposedHeaders: ['Set-Cookie'],
  })
);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        // styleSrc: ["'self'"],
        // styleSrc: ["'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: 'no-referrer' },
    frameguard: { action: 'deny' },
    noSniff: true,
    permittedCrossDomainPolicies: {
      permittedPolicies: 'none',
    },
  })
);

app.use((_req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );
  next();
});

app.use(express.static('dist'));

app.use(cookieParser());

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message:
    'Too many requests from this IP, please try again after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
});

// // Define a stricter rate limit for API routes
// const apiLimiter = rateLimit({
//   windowMs: 1 * 60 * 1000, // 1 minute
//   max: 30,
//   message:
//     'Too many API requests from this IP, please try again after a minute',
//   standardHeaders: true,
//   legacyHeaders: false,
// });

const trustProxyCount = process.env.TRUST_PROXY_COUNT
  ? parseInt(process.env.TRUST_PROXY_COUNT)
  : process.env.NODE_ENV === 'production' ? 1 : 1;
app.set('trust proxy', trustProxyCount);

app.use(globalLimiter);

app.use((req, res, next) => {
  if (
    ['GET', 'HEAD', 'OPTIONS'].includes(req.method) ||
    req.path === '/api/csrf-token' ||
    req.path === '/api/auth/csrf-refresh'
  ) {
    next();
  } else {
    doubleCsrfProtection(req, res, next);
  }
});

const PORT = process.env.PORT;

async function initializeServer() {
  try {
    await AppDataSource.initialize();

    app.use(
      '/api/auth',
      // apiLimiter,
      authRoutes
    );
    app.use(
      '/api/patients',
      //  apiLimiter,
      patientRoutes
    );
    app.use(
      '/api/medical-history',
      // apiLimiter,
      medicalHistoryRoutes
    );
    app.use(
      '/api/dashboard',
      // apiLimiter,
      dashboardRoutes
    );

    app.use(errorHandler);

    if (process.env.NODE_ENV !== 'test') {
      app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
      });
    }
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1);
  }
}

initializeServer();

app.get('/health', (_req, res: Response) => {
  res.status(200).json({
    status: 'UP',
    database: AppDataSource.isInitialized
      ? 'CONNECTED'
      : 'DISCONNECTED',
    timestamp: new Date().toISOString(),
  });
});

import { getJWKS } from './services/keysService';

app.get('/api/csrf-token', (req, res) => {
  try {
    const token = generateCsrfToken(req, res);
    res.json({ csrfToken: token });
  } catch (error) {
    console.error('Error generating CSRF token:', error);
    res.status(500).json({ error: 'CSRF token not available' });
  }
});

app.get('/.well-known/jwks.json', (_req, res) => {
  res.json(getJWKS());
});

export { app, AppDataSource };
