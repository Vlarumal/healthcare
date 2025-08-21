import express, { Application, Response } from 'express';
import cors from 'cors';
// import { QueryRunner } from 'typeorm';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
// import { createCsrfMiddleware } from './middlewares/csrfMiddleware';

// const { doubleCsrfProtection, generateCsrfToken } =
// createCsrfMiddleware();
import patientRoutes from './routes/patientRoutes';
import medicalHistoryRoutes from './routes/medicalHistoryRoutes';
import errorHandler from './middlewares/errorHandler';
import { AppDataSource } from './data-source';
import authRoutes from './routes/authRoutes';
import dashboardRoutes from './routes/dashboardRoutes';
import helmet from 'helmet';
// import rateLimit from 'express-rate-limit';
import logger from './utils/logger';
import { InternalServerError } from './errors/httpErrors';
import path from 'path';
import { getJWKS } from './services/keysService';
import { httpOnly, sameSite } from './config';

// declare global {
//   namespace Express {
//     interface Request {
//       queryRunner?: QueryRunner;
//     }
//   }
// }

dotenv.config();

const app: Application = express();
// app.set('trust proxy', process.env.TRUST_PROXY_COUNT);
// app.set('trust proxy', [
//   '100.20.92.101',
//   '44.225.181.72',
//   '44.227.217.144',
// ]);
app.enable('trust proxy');

app.use(express.json());

if (process.env.NODE_ENV === 'production') {
  if (!process.env.FRONTEND_URL) {
    logger.error('FRONTEND_URL environment variable is not set in production');
    throw new InternalServerError(
      'Internal server error',
      'SERVER_ERROR'
    );
  }
  
  app.use(
    cors({
      origin: process.env.FRONTEND_URL,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
      exposedHeaders: ['Set-Cookie']
    })
  );
} else {
  const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:3001',
    'https://healthcare-2rmw.onrender.com',
    'https://healthcare-as0g.onrender.com',
  ];

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
}

if (
  process.env.HELMET !== undefined &&
  process.env.HELMET.toLowerCase() === 'true'
) {
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: [
            "'self'",
            'https://gc.kis.v2.scr.kaspersky-labs.com',
          ],
          styleSrc: [
            "'self'",
            "'unsafe-inline'",
            'https://gc.kis.v2.scr.kaspersky-labs.com',
          ],
          styleSrcElem: [
            "'self'",
            'http://gc.kis.v2.scr.kaspersky-labs.com',
            'ws://gc.kis.v2.scr.kaspersky-labs.com',
            "'unsafe-inline'",
          ],
          imgSrc: ["'self'", 'data:', 'https://flagcdn.com'],
          connectSrc: [
            "'self'",
            'https://gc.kis.v2.scr.kaspersky-labs.com',
            'https://healthcare-as0g.onrender.com',
            'https://healthcare-2rmw.onrender.com',
          ],
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
}

app.use((_req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );
  next();
});

// const buildPath = path.join(__dirname, 'dist');
// app.use(express.static(buildPath));

app.use(express.static('../frontend/dist'));
// // Serve static files with CORS headers
// app.use(express.static('dist', {
//   setHeaders: (res, path) => {
//     if (path.endsWith('.css')) {
//       res.setHeader('Access-Control-Allow-Origin', '*');
//       res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
//       res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
//     }
//   }
// }));

// const trustProxyCount = process.env.TRUST_PROXY_COUNT
//   ? parseInt(process.env.TRUST_PROXY_COUNT)
//   : process.env.NODE_ENV === 'production'
//   ? 1
//   : 1;
// app.set('trust proxy', trustProxyCount);
// app.set('trust proxy', process.env.NODE_ENV === 'production');
// app.set('trust proxy', process.env.TRUST_PROXY_COUNT);

// Ensure Express respects X-Forwarded-Proto header for secure cookies
// app.enable('trust proxy');

app.use(cookieParser());

// Create session ID first so CSRF middleware can access it
app.use((req, res, next) => {
  if (!req.cookies.sessionId) {
    const sessionId = crypto.randomUUID();
    res.cookie('sessionId', sessionId, {
      httpOnly,
      secure: process.env.NODE_ENV === 'production', // Always true on Render
      sameSite, // 'none' Required for cross-domain like render.com
      maxAge: 86400000, // 24 hours
    });
    req.cookies.sessionId = sessionId;
  }
  next();
});

// const globalLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100,
//   message:
//     'Too many requests from this IP, please try again after 15 minutes',
//   standardHeaders: true,
//   legacyHeaders: false,
// });

// // Define a stricter rate limit for API routes
// const apiLimiter = rateLimit({
//   windowMs: 1 * 60 * 1000, // 1 minute
//   max: 30,
//   message:
//     'Too many API requests from this IP, please try again after a minute',
//   standardHeaders: true,
//   legacyHeaders: false,
// });

// app.use(globalLimiter);

// app.use((req, res, next) => {
//   if (
//     ['GET', 'HEAD', 'OPTIONS'].includes(req.method) ||
//     req.path === '/api/csrf-token' ||
//     req.path === '/api/auth/csrf-refresh'
//   ) {
//     next();
//   } else {
//     if (process.env.CSRF_PROTECTION) {
//       doubleCsrfProtection(req, res, next);
//     }
//   }
// });

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

    app.get(/^(?!\/api).*/, (_req, res) => {
      res.sendFile(
        path.resolve(__dirname, '../../frontend/dist', 'index.html')
      );
    });

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

// app.get('/api/csrf-token', (req, res) => {
//   try {
//     // Ensure sessionId exists before generating token
//     if (!req.cookies.sessionId) {
//       // If sessionId is missing, create one (should be rare since sessionId middleware runs first)
//       const sessionId = crypto.randomUUID();
//       res.cookie('sessionId', sessionId, {
//         httpOnly: true,
//         secure: process.env.NODE_ENV === 'production',
//         sameSite: 'none',
//         maxAge: 86400000 // 24 hours
//       });
//       req.cookies.sessionId = sessionId;
//     }

//     const token = generateCsrfToken(req, res);
//     res.json({ csrfToken: token });
//   } catch (error) {
//     logger.error('Error generating CSRF token:', error);
//     res.status(500).json({ error: 'CSRF token not available' });
//   }
// });

app.get('/.well-known/jwks.json', (_req, res) => {
  res.json(getJWKS());
});

export { app, AppDataSource };
