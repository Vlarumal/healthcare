import express, { Application, Response } from 'express';
import https from 'https';
import http from 'http';
import fs from 'fs';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import path from 'path';
import { doubleCsrfProtection, generateCsrfToken } from './middlewares/csrfInstance';

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
import { getJWKS } from './services/keysService';
// import { httpOnly, sameSite, cookieDomain } from './config';

// Load .env from the project root (works for both src/ and build/ directories)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app: Application = express();

const DIST_PATH = path.resolve(__dirname, '../../frontend/dist');
// const ASSETS_PATH = path.join(DIST_PATH, 'assets');

if (!fs.existsSync(DIST_PATH)) {
  console.error('Frontend dist not found:', DIST_PATH);
  process.exit(1);
}

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
    logger.error(
      'FRONTEND_URL environment variable is not set in production',
    );
    throw new InternalServerError(
      'Internal server error',
      'SERVER_ERROR',
    );
  }

  app.use(
    cors({
      origin: process.env.FRONTEND_URL,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'x-csrf-token',
      ],
      exposedHeaders: ['Set-Cookie'],
    }),
  );
} else {
  const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:4173',
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
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-CSRF-Token',
      ],
      exposedHeaders: ['Set-Cookie'],
    }),
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
    }),
  );
}

app.use((_req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()',
  );
  next();
});

// const buildPath = path.join(__dirname, 'dist');
// app.use(express.static(buildPath));

// app.use(
//   '/assets',
//   express.static(ASSETS_PATH, {
//     fallthrough: true,
//     setHeaders: (res, filePath) => {
//       if (filePath.endsWith('.js')) {
//         res.setHeader(
//           'Content-Type',
//           'application/javascript; charset=utf-8',
//         );
//       } else if (filePath.endsWith('.css')) {
//         res.setHeader('Content-Type', 'text/css; charset=utf-8');
//       } else if (filePath.endsWith('.json')) {
//         res.setHeader(
//           'Content-Type',
//           'application/json; charset=utf-8',
//         );
//       } else if (filePath.endsWith('.map')) {
//         res.setHeader(
//           'Content-Type',
//           'application/json; charset=utf-8',
//         );
//       }
//     },
//   }),
// );

app.use(
  express.static(DIST_PATH, {
    index: false,
  }),
);

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

// Does it require a session cookie like express-session?
// No. The library is designed to work without sessions. The fallback mechanism is intentional.
// // Create session ID first so CSRF middleware can access it
// app.use((req, res, next) => {
//   if (!req.cookies.sessionId) {
//     const sessionId = crypto.randomUUID();

//     const cookieOptions: {
//       httpOnly: boolean;
//       secure: boolean;
//       sameSite: boolean | 'lax' | 'strict' | 'none' | undefined;
//       maxAge: number;
//       domain?: string;
//     } = {
//       httpOnly,
//       secure: process.env.NODE_ENV === 'production', // Always true on Render
//       sameSite, // 'none' Required for cross-domain like render.com
//       maxAge: 86400000, // 24 hours
//     };

//     if (process.env.NODE_ENV === 'production' && cookieDomain) {
//       cookieOptions.domain = cookieDomain;
//     }

//     res.cookie('sessionId', sessionId, cookieOptions);
//     req.cookies.sessionId = sessionId;
//   }

//   // Attach session ID to request for CSRF middleware
//   req.session = req.session || {};
//   req.session.id = req.cookies.sessionId;

//   next();
// });

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

app.use((req, res, next) => {
  if (
    ['GET', 'HEAD', 'OPTIONS'].includes(req.method) ||
    req.path === '/api/csrf-token' ||
    req.path === '/api/auth/csrf-refresh'
  ) {
    next();
  } else {
    if (process.env.CSRF_PROTECTION) {
      doubleCsrfProtection(req, res, next);
    }
  }
});

const PORT = process.env.PORT || 3001;

// HTTP server (for health checks, redirect)
const httpServer = http.createServer(app);

// HTTPS server options
let httpsServer: https.Server | null = null;

if (
  process.env.NODE_ENV === 'production' &&
  process.env.USE_LOCAL_HTTPS === 'true'
) {
  const httpsOptions = {
    key: fs.readFileSync(path.resolve(__dirname, '../../key.pem')),
    cert: fs.readFileSync(path.resolve(__dirname, '../../cert.pem')),
  };

  httpsServer = https.createServer(httpsOptions, app);
}

let serverInitialized = false;

async function initializeServer() {
  // Prevent double initialization
  if (serverInitialized) {
    console.warn('Server already initialized, skipping...');
    return;
  }
  serverInitialized = true;

  try {
    await AppDataSource.initialize();

    app.use(
      '/api/auth',
      // apiLimiter,
      authRoutes,
    );
    app.use(
      '/api/patients',
      //  apiLimiter,
      patientRoutes,
    );
    app.use(
      '/api/medical-history',
      // apiLimiter,
      medicalHistoryRoutes,
    );
    app.use(
      '/api/dashboard',
      // apiLimiter,
      dashboardRoutes,
    );

    app.get(/^(?!\/api).*/, (_req, res) => {
      res.sendFile(
        path.resolve(__dirname, '../../frontend/dist', 'index.html'),
      );
    });

    // SPA fallback (MUST be last)
    // app.get('*', (_req: Request, res: Response) => {
    //   res.sendFile(path.join(DIST_PATH, 'index.html'));
    // });

    app.use(errorHandler);

    if (process.env.NODE_ENV !== 'test') {
      // httpServer.listen(PORT, () => {
      //   console.log(`HTTP Server running on port ${PORT}`);
      // });

      if (httpsServer) {
        httpsServer.listen(3443, () => {
          console.log(`HTTPS Server running on port 3443`);
        });
      } else if (process.env.NODE_ENV === 'production') {
        httpServer.listen(PORT, () => {
          console.log(`Server running on port ${PORT}`);
        });
      } else {
        httpServer.listen(PORT, () => {
          console.log(`HTTP Server running on port ${PORT}`);
        });
      }
    }
  } catch (error) {
    serverInitialized = false; // Reset on error
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

app.get('/api/csrf-token', (req, res) => {
  try {
    // if (!req.session?.id) {
    //   res.status(400).json({ error: 'Session not initialized' });
    //   return;
    // }

    const token = generateCsrfToken(req, res);
    res.json({ csrfToken: token });
  } catch (error) {
    logger.error('Error generating CSRF token:', error);
    res.status(500).json({ error: 'CSRF token not available' });
  }
});

app.get('/.well-known/jwks.json', (_req, res) => {
  res.json(getJWKS());
});

export { app, AppDataSource };
