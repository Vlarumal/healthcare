import { Router } from 'express';
import {
  ACCESS_TOKEN_EXPIRES_IN_MS,
  httpOnly,
  REFRESH_TOKEN_EXPIRES_IN_DAYS,
  REFRESH_TOKEN_EXPIRES_IN_MS,
  sameSite,
} from '../config';
import bcrypt from 'bcrypt';
import logger from '../utils/logger';
import jwt from 'jsonwebtoken';
import { createHmac } from 'crypto';
import asyncHandler from '../utils/asyncHandler';
import { AppDataSource } from '../data-source';
import { Patient, Role } from '../entities/Patient';
import { SignupDTO, LoginDTO } from '../types/auth';
import { authenticateJWT } from '../middlewares/authMiddleware';
import {
  generateTokens,
  storeRefreshToken,
  verifyRefreshToken,
  rotateRefreshToken,
  privateKey,
  revokeToken,
  generateFingerprint,
  revokeAllTokensForUser,
} from '../services/tokenService';
import {
  InternalServerError,
  UnauthorizedError,
} from '../errors/httpErrors';
import { ValidationError } from '../errors/validationError';
import { PasswordService } from '../services/passwordService';
import { setTemporaryPassword } from '../utils/tempPasswordUtils';
import { createCsrfMiddleware } from '../middlewares/csrfMiddleware';
import { validate } from '../middlewares/validationMiddleware';
import {
  signupSchema,
  loginSchema,
  resetPasswordUnauthenticatedSchema,
  requestTempPasswordSchema,
  resetPasswordAuthenticatedSchema,
} from '../schemas/authSchemas';
import { UserNotFoundError } from '../errors/authErrors';
import ErrorLogger from '../utils/errorLogger';

const router = Router();

const getPatientRepository = () =>
  AppDataSource.getRepository(Patient);

let passwordServiceInstance: PasswordService | null = null;

const getPasswordService = () => {
  if (!passwordServiceInstance) {
    passwordServiceInstance = new PasswordService();
  }
  return passwordServiceInstance;
};

export const setPasswordServiceInstance = (
  instance: PasswordService | null
) => {
  passwordServiceInstance = instance;
};

router.post(
  '/signup',
  validate(signupSchema),
  asyncHandler(async (req, res, next) => {
    const {
      firstName,
      lastName,
      email,
      password,
      dateOfBirth,
    }: SignupDTO = req.body;

    try {
      getPasswordService().validatePassword(password);
    } catch (error) {
      if (error instanceof ValidationError) {
        next(error);
        return;
      }
      next(
        new ValidationError([
          {
            field: 'password',
            message: 'Unexpected error during password validation',
          },
        ])
      );
      return;
    }

    const existingPatient = await getPatientRepository().findOne({
      where: { email },
    });
    if (existingPatient) {
      next(
        new ValidationError([
          {
            field: 'email',
            message: 'Email is already registered',
          },
        ])
      );
      return;
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newPatient = getPatientRepository().create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      dateOfBirth,
      role: Role.PATIENT,
    });

    await getPatientRepository().save(newPatient);

    const userAgent = req.headers['user-agent'] ?? '';
    const clientIp = req.ip ?? '';
    const { accessToken, refreshToken } = generateTokens(
      newPatient.id,
      newPatient.role,
      newPatient.passwordVersion,
      userAgent,
      clientIp
    );
    if (!refreshToken) {
      next(
        new InternalServerError('Refresh token is undefined or empty')
      );
      return;
    }
    const decodedRefresh = jwt.decode(refreshToken) as jwt.JwtPayload;
    if (!decodedRefresh || !decodedRefresh.jti) {
      next(
        new InternalServerError(
          `Invalid refresh token: ${refreshToken}`
        )
      );
      return;
    }
    await storeRefreshToken(
      newPatient.id,
      decodedRefresh.jti,
      decodedRefresh.exp! * 1000
    );

    res
      .cookie('accessToken', accessToken, {
        httpOnly,
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
        domain:
          process.env.NODE_ENV === 'production'
            ? process.env.COOKIE_DOMAIN || undefined
            : undefined,
        path: '/',
        maxAge: ACCESS_TOKEN_EXPIRES_IN_MS,
      })
      .cookie('refreshToken', refreshToken, {
        httpOnly,
        path: '/',
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
        domain:
          process.env.NODE_ENV === 'production'
            ? process.env.COOKIE_DOMAIN || undefined
            : undefined,
        maxAge: REFRESH_TOKEN_EXPIRES_IN_DAYS,
        expires: new Date(
          Date.now() +
            REFRESH_TOKEN_EXPIRES_IN_DAYS * 24 * 60 * 60 * 1000
        ),
      });

    const { password: _, ...patientData } = newPatient;
    const responseData = {
      ...patientData,
      dateOfBirth:
        newPatient.dateOfBirth instanceof Date
          ? newPatient.dateOfBirth.toISOString().split('T')[0]
          : newPatient.dateOfBirth,
    };
    res.status(201).json(responseData);
  })
);

router.post(
  '/login',
  validate(loginSchema),
  asyncHandler(async (req, res, next) => {
    const { email, password }: LoginDTO = req.body;

    const patient = await getPatientRepository().findOne({
      where: { email },
      select: ['id', 'email', 'password', 'passwordVersion', 'role'],
    });

    if (!patient) {
      return res.status(401).json({
        error: 'Invalid credentials',
      });
    }

    let isTemporaryPassword = false;
    if (patient.temporaryPassword) {
      isTemporaryPassword = await bcrypt.compare(
        password,
        patient.temporaryPassword
      );
    }

    const passwordMatch =
      isTemporaryPassword ||
      (await bcrypt.compare(password, patient.password));

    if (!passwordMatch) {
      return res.status(401).json({
        error: 'Invalid credentials',
      });
    }

    if (isTemporaryPassword || patient.resetRequired) {
      const userAgent = req.headers['user-agent'] ?? '';
      const clientIp = req.ip ?? '';
      const { accessToken } = generateTokens(
        patient.id,
        patient.role,
        patient.passwordVersion,
        userAgent,
        clientIp
      );

      res.cookie('accessToken', accessToken, {
        httpOnly,
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
        maxAge: 5 * 60 * 1000, // 5 minutes
      });

      res.status(200).json({ resetRequired: true });
      return;
    }

    try {
      const revokeResult = await revokeAllTokensForUser(patient.id);
      if (revokeResult === 0) {
        logger.info(`No tokens revoked for user ${patient.id}`);
      }
    } catch (error) {
      ErrorLogger.logError(error, {
        userId: patient.id,
        message: 'Token revocation failed',
      });
      ErrorLogger.logWarning(
        'Proceeding with login despite token revocation failure',
        { userId: patient.id }
      );
    }

    const userAgent = req.headers['user-agent'] ?? '';
    const clientIp = req.ip ?? '';
    const { accessToken, refreshToken } = generateTokens(
      patient.id,
      patient.role,
      patient.passwordVersion,
      userAgent,
      clientIp
    );
    if (!refreshToken) {
      next(
        new InternalServerError('Refresh token is undefined or empty')
      );
      return;
    }
    const decodedRefresh = jwt.decode(refreshToken) as jwt.JwtPayload;
    if (!decodedRefresh || !decodedRefresh.jti) {
      next(
        new InternalServerError(
          `Invalid refresh token: ${refreshToken}`
        )
      );
      return;
    }
    await storeRefreshToken(
      patient.id,
      decodedRefresh.jti,
      decodedRefresh.exp! * 1000
    );

    res
      .cookie('accessToken', accessToken, {
        httpOnly,
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
        domain:
          process.env.NODE_ENV === 'production'
            ? process.env.COOKIE_DOMAIN || undefined
            : undefined,
        path: '/',
        maxAge: ACCESS_TOKEN_EXPIRES_IN_MS,
      })
      .cookie('refreshToken', refreshToken, {
        httpOnly,
        path: '/',
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
        domain:
          process.env.NODE_ENV === 'production'
            ? process.env.COOKIE_DOMAIN || undefined
            : undefined,
        maxAge: REFRESH_TOKEN_EXPIRES_IN_MS,
      });

    const {
      password: _,
      dateOfBirth: __,
      ...essentialData
    } = patient;
    res.status(200).json(essentialData);
  })
);

router.get('/csrf-refresh', (req, res) => {
  try {
    const { generateCsrfToken } = createCsrfMiddleware();
    const token = generateCsrfToken(req, res);
    res.json({ csrfToken: token });
  } catch (error) {
    res.status(500).json({ error: 'Failed to refresh CSRF token' });
  }
});

router.get(
  '/me',
  authenticateJWT,
  asyncHandler(async (req, res, next) => {
    const patient = await getPatientRepository().findOne({
      where: { id: req.user!.id },
      relations: ['medicalHistories'],
    });

    if (!patient) {
      next(new UserNotFoundError());
      return;
    }

    const serializePatient = (patient: Patient) => {
      const { password, passwordVersion, ...rest } = patient;
      return {
        ...rest,
        dateOfBirth:
          patient.dateOfBirth instanceof Date
            ? patient.dateOfBirth.toISOString().split('T')[0]
            : patient.dateOfBirth,
      };
    };

    res.json(serializePatient(patient));
  })
);

router.get(
  '/validate-token',
  authenticateJWT,
  asyncHandler(async (_req, res) => {
    res.status(200).json({ valid: true });
  })
);

router.post(
  '/refresh',
  asyncHandler(async (req, res, next) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Missing refresh token' });
    }

    const userAgent = req.headers['user-agent'] ?? '';
    const clientIp = req.ip ?? '';
    const currentFingerprint = generateFingerprint(
      userAgent,
      clientIp
    );

    let payload: any;
    try {
      payload = await verifyRefreshToken(
        refreshToken,
        currentFingerprint
      );
    } catch (error) {
      next(new UnauthorizedError('Invalid refresh token'));
      return;
    }

    const newRefreshToken = await rotateRefreshToken(
      payload.userId,
      payload.jti!,
      userAgent,
      clientIp
    );
    if (!newRefreshToken) {
      next(
        new InternalServerError('Refresh token is undefined or empty')
      );
      return;
    }
    const decodedRefresh = jwt.decode(
      newRefreshToken
    ) as jwt.JwtPayload;
    if (!decodedRefresh || !decodedRefresh.jti) {
      next(
        new InternalServerError(
          `Invalid refresh token: ${newRefreshToken}`
        )
      );
      return;
    }

    const patientRepo = AppDataSource.getRepository(Patient);
    const patient = await patientRepo.findOneBy({
      id: payload.userId,
    });
    if (!patient) {
      next(new UserNotFoundError());
      return;
    }

    const tokenVersionHash = createHmac(
      'sha256',
      process.env.TOKEN_VERSION || ''
    )
      .update('v1')
      .digest('hex');

    const jwtOptions: jwt.SignOptions = {
      algorithm: 'RS256',
    };

    if (process.env.NODE_ENV === 'test') {
      jwtOptions.expiresIn = '5s';
    } else {
      jwtOptions.expiresIn = '25m';
    }

    const accessToken = jwt.sign(
      {
        sub: patient.id.toString(),
        role: patient.role,
        passwordVersion: patient.passwordVersion,
        tokenVersionHash,
        fingerprint: currentFingerprint,
      },
      privateKey,
      jwtOptions
    );

    res
      .cookie('accessToken', accessToken, {
        httpOnly,
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
        path: '/',
        maxAge: ACCESS_TOKEN_EXPIRES_IN_MS,
        expires: new Date(Date.now() + ACCESS_TOKEN_EXPIRES_IN_MS),
      })
      .cookie('refreshToken', newRefreshToken, {
        httpOnly,
        path: '/',
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
        maxAge: REFRESH_TOKEN_EXPIRES_IN_MS,
      })
      .status(200)
      .json({
        accessToken,
        refreshToken: newRefreshToken,
      });
  })
);

router.post(
  '/reset-password-authenticated',
  authenticateJWT,
  validate(resetPasswordAuthenticatedSchema),
  asyncHandler(async (req, res, next) => {
    const { newPassword } = req.body;
    const userId = req.user!.id;

    getPasswordService().validatePassword(newPassword);

    const patientRepo = getPatientRepository();
    const patient = await patientRepo.findOne({
      where: { id: userId },
      select: [
        'id',
        'password',
        'temporaryPassword',
        'resetRequired',
        'role',
        'passwordVersion',
      ],
    });

    if (!patient) {
      next(new UserNotFoundError());
      return;
    }

    const hashedPassword = await getPasswordService().hashPassword(
      newPassword
    );

    patient.password = hashedPassword;
    patient.temporaryPassword = null;
    patient.resetRequired = false;
    patient.passwordVersion += 1; // Invalidate old tokens

    await patientRepo.save(patient);

    const userAgent = req.headers['user-agent'] ?? '';
    const clientIp = req.ip ?? '';
    const { accessToken, refreshToken } = generateTokens(
      patient.id,
      patient.role,
      patient.passwordVersion,
      userAgent,
      clientIp
    );
    if (!refreshToken) {
      next(
        new InternalServerError('Refresh token is undefined or empty')
      );
      return;
    }
    const decodedRefresh = jwt.decode(refreshToken) as jwt.JwtPayload;
    if (!decodedRefresh || !decodedRefresh.jti) {
      next(
        new InternalServerError(
          `Invalid refresh token: ${refreshToken}`
        )
      );
      return;
    }
    await storeRefreshToken(
      patient.id,
      decodedRefresh.jti,
      decodedRefresh.exp! * 1000
    );

    res
      .cookie('accessToken', accessToken, {
        httpOnly,
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
        path: '/',
        maxAge: ACCESS_TOKEN_EXPIRES_IN_MS,
      })
      .cookie('refreshToken', refreshToken, {
        httpOnly,
        path: '/',
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
        maxAge: REFRESH_TOKEN_EXPIRES_IN_MS, // 7 days
      });

    res.status(200).json({ message: 'Password reset successful' });
  })
);

router.post(
  '/reset-password',
  validate(resetPasswordUnauthenticatedSchema),
  asyncHandler(async (req, res, next) => {
    const { email, newPassword } = req.body;

    try {
      getPasswordService().validatePassword(newPassword);

      const patientRepo = getPatientRepository();
      const patient = await patientRepo.findOne({
        where: { email },
        select: [
          'id',
          'password',
          'temporaryPassword',
          'resetRequired',
          'role',
          'passwordVersion',
        ],
      });

      if (!patient) {
        next(new UserNotFoundError());
        return;
      }

      const hashedPassword = await getPasswordService().hashPassword(
        newPassword
      );

      patient.password = hashedPassword;
      patient.temporaryPassword = null;
      patient.resetRequired = false;
      patient.passwordVersion += 1; // Invalidate old tokens

      await patientRepo.save(patient);

      res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
      if (error instanceof ValidationError) {
        return res.status(400).json({
          message: 'Validation failed',
          details: { errors: error.details },
        });
      }
      next(error);
    }
  })
);

router.post(
  '/request-temp-password',
  validate(requestTempPasswordSchema),
  asyncHandler(async (req, res) => {
    const { email } = req.body;

    res.status(202).json({
      message:
        'If the email is registered, a temporary password will be sent shortly',
    });

    try {
      const patientRepo = getPatientRepository();
      const patient = await patientRepo.findOne({ where: { email } });

      if (patient) {
        await setTemporaryPassword(patient.email);
      }
    } catch (error) {
      ErrorLogger.logError(error, {
        message: 'Error in background task for temporary password',
      });
    }
  })
);

router.post(
  '/logout',
  asyncHandler(async (req, res, _next) => {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      try {
        const payload = (await verifyRefreshToken(
          refreshToken
        )) as jwt.JwtPayload;
        if (payload?.jti) {
          await revokeToken(payload.userId, payload.jti);
        }
      } catch (error) {
        const message =
          error instanceof Error ? error.message : 'Unknown error';
        ErrorLogger.logWarning(message, {
          message: 'Invalid refresh token during logout',
        });
      }
    }

    // const { generateCsrfToken } = createCsrfMiddleware();
    // generateCsrfToken(req, res, { overwrite: true });

    res
      .clearCookie('accessToken', {
        httpOnly,
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
      })
      .clearCookie('refreshToken', {
        httpOnly,
        path: '/',
        secure:
          process.env.NODE_ENV === 'production' &&
          process.env.PROXY_SECURE === 'true',
        sameSite,
      });

    res.status(204).send();
  })
);

export default router;
