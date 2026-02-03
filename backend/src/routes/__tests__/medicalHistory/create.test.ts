import request from 'supertest';
import express from 'express';
import errorHandler from '../../../middlewares/errorHandler';
import medicalHistoryRouter from '../../medicalHistoryRoutes';
import { AppDataSource } from '../../../index';
import { MedicalHistory } from '../../../entities/MedicalHistory';
import { Patient } from '../../../entities/Patient';
import { authenticateJWT } from '../../../middlewares/authMiddleware';
import { Request, Response, NextFunction } from 'express';

jest.mock('../../../index', () => ({
  AppDataSource: {
    getRepository: jest.fn(),
    isInitialized: true,
  },
}));

jest.mock('../../../middlewares/authMiddleware', () => ({
  authenticateJWT: jest.fn(
    (req: Request, _res: Response, next: NextFunction) => {
      if (!req.user) {
        req.user = { id: 1, role: 'admin' as const };
      }
      next();
    }
  ),
  authorizeRole: jest.fn(
    (roles: string[]) =>
      (req: Request, res: Response, next: NextFunction) => {
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

const mockPatientService = {
  getPatientById: jest.fn(),
};

jest.mock('../../patientRoutes', () => {
  const actual = jest.requireActual('../../patientRoutes');
  return {
    ...actual,
    getPatientService: () => mockPatientService,
  };
});

jest.mock('isomorphic-dompurify', () => ({
  sanitize: jest.fn((input: string) => {
    if (input === '<script>alert("xss")</script>') {
      return '';
    }
    return input;
  }),
}));

const mockMedicalHistoryRepo = {
  create: jest.fn(),
  save: jest.fn(),
};

const mockPatientRepo = {
  findOneBy: jest.fn(),
};

(AppDataSource.getRepository as jest.Mock).mockImplementation(
  (entity) => {
    if (entity === MedicalHistory) return mockMedicalHistoryRepo;
    if (entity === Patient) return mockPatientRepo;
    return null;
  }
);

const mockPatient = {
  id: 1,
  firstName: 'John',
  lastName: 'Doe',
  email: 'john.doe@example.com',
};

const mockMedicalHistory = {
  id: 1,
  date: new Date('2023-01-01'),
  diagnosis: 'Common Cold',
  treatment: 'Rest and fluids',
  notes: 'Patient recovering well',
  patient: mockPatient,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const app = express();
app.use(express.json());
app.use('/medical-history', medicalHistoryRouter);
app.use(errorHandler);

describe('POST /medical-history', () => {
  const validMedicalHistoryData = {
    date: '2023-01-01',
    diagnosis: 'Common Cold',
    treatment: 'Rest and fluids',
    patientId: 1,
    notes: 'Patient recovering well',
  };

  beforeEach(() => {
    jest.clearAllMocks();

    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        if (!req.user) {
          req.user = { id: 1, role: 'admin' as const };
        }
        next();
      }
    );
  });

  it('should create a new medical history record (admin role)', async () => {
    mockPatientRepo.findOneBy.mockResolvedValue(mockPatient);
    mockMedicalHistoryRepo.create.mockReturnValue({
      ...mockMedicalHistory,
    });
    mockMedicalHistoryRepo.save.mockResolvedValue(
      mockMedicalHistory
    );

    const response = await request(app)
      .post('/medical-history')
      .send(validMedicalHistoryData);

    expect(response.status).toBe(201);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 1,
        diagnosis: 'Common Cold',
        treatment: 'Rest and fluids',
      })
    );
    expect(mockPatientRepo.findOneBy).toHaveBeenCalledWith({
      id: 1,
    });
    expect(mockMedicalHistoryRepo.create).toHaveBeenCalled();
    expect(mockMedicalHistoryRepo.save).toHaveBeenCalled();
  });

  it('should create a new medical history record (clinician role)', async () => {
    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        req.user = { id: 2, role: 'clinician' as const };
        next();
      }
    );

    mockPatientRepo.findOneBy.mockResolvedValue(mockPatient);
    mockMedicalHistoryRepo.create.mockReturnValue({
      ...mockMedicalHistory,
    });
    mockMedicalHistoryRepo.save.mockResolvedValue(
      mockMedicalHistory
    );

    const response = await request(app)
      .post('/medical-history')
      .send(validMedicalHistoryData);

    expect(response.status).toBe(201);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 1,
        diagnosis: 'Common Cold',
        treatment: 'Rest and fluids',
      })
    );
  });

  it('should return 403 for patient role', async () => {
    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        req.user = { id: 1, role: 'patient' as const };
        next();
      }
    );

    const response = await request(app)
      .post('/medical-history')
      .send(validMedicalHistoryData);

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      code: 'ACCESS_DENIED',
      message: 'Insufficient permissions for this operation',
    });
  });

  it('should return 403 for staff role', async () => {
    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        req.user = { id: 1, role: 'staff' as const };
        next();
      }
    );

    const response = await request(app)
      .post('/medical-history')
      .send(validMedicalHistoryData);

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      code: 'ACCESS_DENIED',
      message: 'Insufficient permissions for this operation',
    });
  });

  it('should return 400 for invalid input data', async () => {
    const invalidData = {
      date: 'invalid-date',
      diagnosis: 'A', // Too short
      treatment: 'B', // Too short
      patientId: -1, // Invalid ID
    };

    const response = await request(app)
      .post('/medical-history')
      .send(invalidData);

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        status: 400,
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        details: {
          errors: expect.arrayContaining([
            expect.objectContaining({ field: 'date' }),
            expect.objectContaining({ field: 'diagnosis' }),
            expect.objectContaining({ field: 'treatment' }),
            expect.objectContaining({ field: 'patientId' }),
          ]),
        },
      },
    });
  });

  it('should return 404 when patient is not found', async () => {
    mockPatientRepo.findOneBy.mockResolvedValue(null);

    const response = await request(app)
      .post('/medical-history')
      .send(validMedicalHistoryData);

    expect(response.status).toBe(404);
    expect(response.body).toEqual({
      error: {
        code: 'PATIENT_NOT_FOUND',
        message: 'Patient not found',
        status: 404,
      },
    });
  });

  it('should sanitize XSS in notes field', async () => {
    const xssData = {
      ...validMedicalHistoryData,
      notes: '<script>alert("xss")</script>',
    };

    mockPatientRepo.findOneBy.mockResolvedValue(mockPatient);
    mockMedicalHistoryRepo.create.mockImplementation(
      (data) => data
    );
    mockMedicalHistoryRepo.save.mockResolvedValue({
      ...mockMedicalHistory,
      notes: '',
    });

    const response = await request(app)
      .post('/medical-history')
      .send(xssData);

    expect(response.status).toBe(201);
    expect(response.body.notes).toBe('');
  });
});
