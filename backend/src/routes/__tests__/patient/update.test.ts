import request from 'supertest';
import express from 'express';
import { Gender } from '../../../entities/Patient';
import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../../../types/express.d';
import { PatientNotFoundError } from '../../../errors/patientErrors';

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

jest.mock('../../../services/passwordService', () => ({
  PasswordService: jest.fn(),
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
import errorHandler from '../../../middlewares/errorHandler';
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
  address?: string;
  city?: string;
  zipCode?: string;
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

describe('PUT /patients/:id', () => {
  it('should successfully update a patient with valid data', async () => {
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
      firstName: 'Jane',
      lastName: 'Smith',
      email: 'jane.smith@example.com',
    };
    mockPatientService.updatePatient.mockResolvedValueOnce(
      updatedPatient
    );

    const response = await request(app).put('/patients/1').send({
      firstName: 'Jane',
      lastName: 'Smith',
      email: 'jane.smith@example.com',
      dateOfBirth: '1995-05-15',
      gender: Gender.FEMALE,
      phoneNumber: '+15559876543',
      address: '123 Main St',
      city: 'Anytown',
      zipCode: '12345',
    });

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
      })
    );
    expect(mockPatientService.updatePatient).toHaveBeenCalledWith(
      1,
      expect.objectContaining({
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
      }),
      { id: 1 }
    );
  });

  it('should return 403 for unauthorized roles', async () => {
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

    const response = await request(app).put('/patients/1').send({
      firstName: 'Jane',
      lastName: 'Smith',
      email: 'jane.smith@example.com',
    });

    expect(response.status).toBe(403);
    expect(response.body).toEqual(
      expect.objectContaining({
        code: 'ACCESS_DENIED',
        message: 'Insufficient permissions for this operation',
      })
    );
  });

  it('should return 400 for validation errors', async () => {
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

    const response = await request(app).put('/patients/1').send({
      email: 'invalid-email',
      dateOfBirth: 'invalid-date',
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

  it('should return 409 for duplicate email errors', async () => {
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

    mockPatientService.updatePatient.mockImplementationOnce(
      async () => {
        const error: any = new Error(
          'duplicate key value violates unique constraint'
        );
        error.code = '23505';
        throw error;
      }
    );

    const response = await request(app).put('/patients/1').send({
      email: 'duplicate@example.com',
    });

    expect(response.status).toBe(409);
    expect(response.body).toEqual(
      expect.objectContaining({
        error: expect.objectContaining({
          code: 'DUPLICATE_EMAIL',
          message: 'Email already exists',
        }),
      })
    );
  });

  it('should return 400 for invalid patient ID', async () => {
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

    const response = await request(app)
      .put('/patients/invalid')
      .send({
        firstName: 'Jane',
        lastName: 'Smith',
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual(
      expect.objectContaining({
        error: expect.objectContaining({
          code: 'INVALID_PATIENT_ID',
          message: 'Invalid patient ID',
        }),
      })
    );
  });

  it('should return 404 when patient is not found', async () => {
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

    mockPatientService.updatePatient.mockImplementationOnce(
      async () => {
        throw new PatientNotFoundError();
      }
    );

    const response = await request(app).put('/patients/999').send({
      firstName: 'Jane',
      lastName: 'Smith',
    });

    expect(response.status).toBe(404);
    expect(response.body).toEqual(
      expect.objectContaining({
        error: expect.objectContaining({
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        }),
      })
    );
  });

  it('should handle empty update data gracefully', async () => {
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

    mockPatientService.getPatientById.mockResolvedValueOnce(
      mockPatient
    );

    const response = await request(app).put('/patients/1').send({});

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 1,
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
      })
    );
  });

  it('should handle null values for optional fields', async () => {
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
      address: null,
      city: null,
      zipCode: null,
      phoneNumber: null,
    };
    mockPatientService.updatePatient.mockResolvedValueOnce(
      updatedPatient
    );

    const response = await request(app).put('/patients/1').send({
      address: null,
      city: null,
      zipCode: null,
      phoneNumber: null,
    });

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        address: null,
        city: null,
        zipCode: null,
        phoneNumber: null,
      })
    );
  });
});

describe('ZIP Code Handling', () => {
  it('should accept valid ZIP codes', async () => {
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
      zipCode: '12345',
    };
    mockPatientService.updatePatient.mockResolvedValueOnce(
      updatedPatient
    );

    const response = await request(app).put('/patients/1').send({
      zipCode: '12345',
    });

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        zipCode: '12345',
      })
    );
  });

  it('should reject invalid ZIP codes', async () => {
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

    const response = await request(app).put('/patients/1').send({
      zipCode: 'invalid-zip',
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

  it('should handle ZIP codes with optional +4 extension', async () => {
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
      zipCode: '12345-6789',
    };
    mockPatientService.updatePatient.mockResolvedValueOnce(
      updatedPatient
    );

    const response = await request(app).put('/patients/1').send({
      zipCode: '12345-6789',
    });

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        zipCode: '12345-6789',
      })
    );
  });
});
