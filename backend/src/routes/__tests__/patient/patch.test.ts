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


import patientRouter from '../../patientRoutes';
import { PatientService } from '../../../services/PatientService';
import { authorizeRole } from '../../../middlewares/authMiddleware';
import errorHandler from '../../../middlewares/errorHandler';


interface MockPatient {
  id: number;
  firstName: string;
  lastName: string;
  email: string;
  dateOfBirth: Date;
  gender: Gender;
  phoneNumber: string;
  password: string;
  role?: string;
}

interface MockPatientService {
  updatePatient: jest.Mock;
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
    updatePatient: jest.fn().mockImplementation((_id, updateData) => {
      return Promise.resolve({ ...mockPatient, ...updateData });
    }),
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
app.use(errorHandler);

describe('Role Modification Authorization', () => {
  it('should prevent non-admin users from modifying roles', async () => {
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
          role: 'clinician' as const,
          tokenVersion: 0,
        };
        next();
      }
    );

    const response = await request(app).patch('/patients/1').send({
      role: 'admin',
    });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        code: 'ACCESS_DENIED',
        message: 'Only administrators can modify user roles',
        status: 403,
      },
    });
  });

  it('should allow admin users to modify roles', async () => {
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
          role: 'admin' as const,
          tokenVersion: 0,
        };
        next();
      }
    );

    const updatedPatient = {
      ...mockPatient,
      role: 'clinician',
    };
    mockPatientService.updatePatient.mockResolvedValueOnce(
      updatedPatient
    );

    const response = await request(app).patch('/patients/1').send({
      role: 'clinician',
    });

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        role: 'clinician',
      })
    );
  });
});

describe('PATCH /patients/:id - Role Modification', () => {
  it('should successfully modify a patient role when requested by admin', async () => {
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
          role: 'admin' as const,
          tokenVersion: 0,
        };
        next();
      }
    );

    const updatedPatient = {
      ...mockPatient,
      id: 2,
      role: 'staff',
    };
    mockPatientService.updatePatient.mockResolvedValueOnce(
      updatedPatient
    );

    const response = await request(app).patch('/patients/2').send({
      role: 'staff',
    });

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 2,
        role: 'staff',
      })
    );
    expect(mockPatientService.updatePatient).toHaveBeenCalledWith(
      2,
      expect.objectContaining({
        role: 'staff',
      }),
      { id: 1 }
    );
  });

  it('should return 403 when non-admin tries to modify role', async () => {
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

    const response = await request(app).patch('/patients/1').send({
      role: 'admin',
    });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        code: 'ACCESS_DENIED',
        message: 'Only administrators can modify user roles',
        status: 403,
      },
    });
  });

  it('should return 400 for invalid role values', async () => {
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
          role: 'admin' as const,
          tokenVersion: 0,
        };
        next();
      }
    );

    const response = await request(app).patch('/patients/1').send({
      role: 'invalid-role',
    });

    expect(response.status).toBe(400);
    expect(response.body).toEqual(
      expect.objectContaining({
        error: expect.objectContaining({
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
        }),
      })
    );
  });
});
