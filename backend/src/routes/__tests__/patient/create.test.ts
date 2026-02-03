import request from 'supertest';
import express from 'express';
import { Gender } from '../../../entities/Patient';
import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../../../types/express.d';

// Mock index module first
jest.mock('../../../index', () => ({
  AppDataSource: {
    isInitialized: true,
    getRepository: jest.fn(),
  },
}));

// Mock logger and errorLogger
jest.mock('../../../utils/logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
}));

jest.mock('../../../utils/errorLogger', () => ({
  default: {
    logError: jest.fn(),
  },
}));

// Mock services
jest.mock('../../../services/PatientService', () => ({
  PatientService: jest.fn(),
  resetPatientService: jest.fn(),
}));

jest.mock('../../../services/AuditService', () => ({
  AuditService: jest.fn(),
}));

jest.mock('../../../services/passwordService', () => ({
  PasswordService: jest.fn(),
}));

jest.mock('../../../services/emailService', () => ({
  EmailService: jest.fn(),
}));

jest.mock('../../../middlewares/authMiddleware', () => ({
  authenticateJWT: jest.fn(
    (
      req: any,
      _res: Response,
      next: NextFunction
    ) => {
      if (!req.user) {
        req.user = { id: 1, role: 'admin' as const, tokenVersion: 0 };
      }
      if (req.testError) {
        next(req.testError);
      } else {
        next();
      }
    }
  ),
  authorizeRole: jest.fn(
    (roles: string[]) =>
      (
        req: any,
        res: Response,
        next: NextFunction
      ) => {
        if (!req.user?.role || !roles.includes(req.user.role)) {
          res.status(403).json({
            code: 'ACCESS_DENIED',
            message: 'Insufficient permissions for this operation',
          });
          return;
        }
        next();
      }
  ),
}));

// Import route after mocks are set up
import patientRouter from '../../patientRoutes';
import { PatientService } from '../../../services/PatientService';
import { AuditService } from '../../../services/AuditService';
import { PasswordService } from '../../../services/passwordService';
import { EmailService } from '../../../services/emailService';
import { authorizeRole } from '../../../middlewares/authMiddleware';

interface MockPatient {
  id: number;
  firstName: string;
  lastName: string;
  email: string;
  dateOfBirth: Date;
  gender: Gender;
  phoneNumber: string;
  password: string;
}

interface MockPatientService {
  createPatient: jest.Mock;
}

interface MockAuditService {
  logPatientAction: jest.Mock;
}

interface MockPasswordService {
  hashPassword: jest.Mock;
}

interface MockEmailService {
  sendWelcomeEmail: jest.Mock;
}

let mockPatient: MockPatient;
let mockPatientService: MockPatientService;
let mockAuditService: MockAuditService;
let mockPasswordService: MockPasswordService;
let mockEmailService: MockEmailService;

beforeEach(() => {
  mockPatient = {
    id: 1,
    firstName: 'John',
    lastName: 'Doe',
    email: 'john.doe@example.com',
    dateOfBirth: new Date('1990-01-01'),
    gender: Gender.MALE,
    phoneNumber: '123-456-7890',
    password: 'hashedpassword',
  };

  mockPatientService = {
    createPatient: jest.fn().mockImplementation((data) => {
      return Promise.resolve({ ...mockPatient, ...data });
    }),
  };

  mockAuditService = {
    logPatientAction: jest.fn().mockResolvedValue(undefined),
  };

  mockPasswordService = {
    hashPassword: jest.fn().mockResolvedValue('hashedpassword'),
  };

  mockEmailService = {
    sendWelcomeEmail: jest.fn().mockResolvedValue(true),
  };

  (PatientService as jest.Mock).mockImplementation(
    () => mockPatientService
  );
  (AuditService as jest.Mock).mockImplementation(
    () => mockAuditService
  );
  (PasswordService as jest.Mock).mockImplementation(
    () => mockPasswordService
  );
  (EmailService as jest.Mock).mockImplementation(
    () => mockEmailService
  );

  const { resetPatientService } = jest.requireActual(
    '../../patientRoutes'
  );
  resetPatientService();
});

afterEach(() => {
  jest.clearAllMocks();
  (authorizeRole as jest.Mock).mockRestore();
});

const app = express();
app.use(express.json());
app.use('/patients', patientRouter);

describe('POST /patients', () => {
  it('should create a new patient (admin/clinician)', async () => {
    mockPatientService.createPatient.mockResolvedValue(mockPatient);

    const response = await request(app).post('/patients').send({
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      password: 'Str0ng!Pass',
      dateOfBirth: '1990-01-01',
      gender: Gender.MALE,
      phoneNumber: '+15551234567',
    });

    expect(response.status).toBe(201);
    expect(response.body).toEqual(
      expect.objectContaining({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
      })
    );
    expect(mockPatientService.createPatient).toHaveBeenCalledWith(
      expect.objectContaining({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
      }),
      { id: 1 }
    );
  });

  it('should return 403 for unauthorized role', async () => {
    (authorizeRole as jest.Mock).mockImplementation(
      () =>
        (
          _req: AuthenticatedRequest,
          res: Response,
          _next: NextFunction
        ) => {
          res.status(403).json({
            code: 'ACCESS_DENIED',
            message: 'Insufficient permissions for this operation',
          });
          return;
        }
    );
    mockPatientService.createPatient.mockImplementationOnce(() => {
      throw new Error('Should not be called');
    });

    const mockAuthenticateJWT = jest.requireMock(
      '../../../middlewares/authMiddleware'
    ).authenticateJWT;
    mockAuthenticateJWT.mockImplementationOnce(
      (
        req: AuthenticatedRequest,
        _res: Response,
        next: NextFunction
      ) => {
        req.user = {
          id: 1,
          role: 'patient' as const,
          tokenVersion: 0,
        };
        next();
      }
    );

    const response = await request(app).post('/patients').send({
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      password: 'Str0ng!Pass',
      dateOfBirth: '1990-01-01',
      phoneNumber: '+15551234567',
    });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      code: 'ACCESS_DENIED',
      message: 'Insufficient permissions for this operation',
    });
    expect(mockPatientService.createPatient).not.toHaveBeenCalled();
  });

  it('should return 500 if database is not initialized in POST endpoint', async () => {
    const mockAppDataSource =
      jest.requireMock('../../../index').AppDataSource;
    const originalIsInitialized = mockAppDataSource.isInitialized;
    mockAppDataSource.isInitialized = false;

    const response = await request(app).post('/patients').send({
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      password: 'Str0ng!Pass',
      dateOfBirth: '1990-01-01',
      gender: Gender.MALE,
      phoneNumber: '+15551234567',
    });

    expect(response.status).toBe(500);

    mockAppDataSource.isInitialized = originalIsInitialized;
  });
});
