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
  getPatientById: jest.Mock;
}

let mockPatient: MockPatient;
let mockPatientService: MockPatientService;

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
    getPatientById: jest.fn().mockResolvedValue(mockPatient),
  };

  (PatientService as jest.Mock).mockImplementation(
    () => mockPatientService
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

describe('verifyPatientOwnership Middleware', () => {
  it('should allow access when patient accesses their own record via /patients/me', async () => {
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

    mockPatientService.getPatientById.mockResolvedValueOnce({
      ...mockPatient,
      id: 1,
    });

    const response = await request(app).get('/patients/me');

    expect(response.status).toBe(200);
    expect(response.body.id).toBe(1);
  });

  it('should allow admin to access any patient record', async () => {
    const mockAuthenticateJWT = jest.requireMock(
      '../../../middlewares/authMiddleware'
    ).authenticateJWT;
    mockAuthenticateJWT.mockImplementationOnce(
      (
        req: AuthenticatedRequest,
        _res: Response,
        next: NextFunction
      ) => {
        req.user = { id: 2, role: 'admin' as const, tokenVersion: 0 };
        next();
      }
    );

    mockPatientService.getPatientById.mockResolvedValueOnce({
      ...mockPatient,
      id: 1,
    });

    const response = await request(app).get('/patients/1');

    expect(response.status).toBe(200);
    expect(response.body.id).toBe(1);
  });

  it('should allow clinician to access any patient record', async () => {
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
          id: 2,
          role: 'clinician' as const,
          tokenVersion: 0,
        };
        next();
      }
    );

    mockPatientService.getPatientById.mockResolvedValueOnce({
      ...mockPatient,
      id: 1,
    });

    const response = await request(app).get('/patients/1');

    expect(response.status).toBe(200);
    expect(response.body.id).toBe(1);
  });

  it('should allow staff to access any patient record', async () => {
    const mockAuthenticateJWT = jest.requireMock(
      '../../../middlewares/authMiddleware'
    ).authenticateJWT;
    mockAuthenticateJWT.mockImplementationOnce(
      (
        req: AuthenticatedRequest,
        _res: Response,
        next: NextFunction
      ) => {
        req.user = { id: 2, role: 'staff' as const, tokenVersion: 0 };
        next();
      }
    );

    mockPatientService.getPatientById.mockResolvedValueOnce({
      ...mockPatient,
      id: 1,
    });

    const response = await request(app).get('/patients/1');

    expect(response.status).toBe(200);
    expect(response.body.id).toBe(1);
  });
});
