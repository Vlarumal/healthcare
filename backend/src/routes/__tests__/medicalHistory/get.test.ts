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

const mockMedicalHistoryRepo = {
  findOne: jest.fn(),
};

const mockPatientRepo = {
  findOne: jest.fn(),
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

describe('GET /medical-history/:id', () => {
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

  it('should return medical history by ID (admin role)', async () => {
    // Mock the patient service getPatientById method to return the mock patient
    // This is needed because verifyMedicalHistoryAccess middleware calls PatientService.getPatientById
    mockPatientService.getPatientById.mockResolvedValue(
      mockPatient
    );
    mockMedicalHistoryRepo.findOne.mockResolvedValue(
      mockMedicalHistory
    );

    const response = await request(app).get('/medical-history/1');

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 1,
        diagnosis: 'Common Cold',
      })
    );
    expect(mockPatientService.getPatientById).toHaveBeenCalledWith(
      1,
      { id: 1 }
    );
    expect(mockMedicalHistoryRepo.findOne).toHaveBeenCalledWith({
      where: { id: 1 },
      relations: ['patient'],
    });
  });

  it('should return medical history by ID (clinician role)', async () => {
    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        req.user = { id: 2, role: 'clinician' as const };
        next();
      }
    );

    mockPatientService.getPatientById.mockResolvedValue(
      mockPatient
    );
    mockMedicalHistoryRepo.findOne.mockResolvedValue(
      mockMedicalHistory
    );

    const response = await request(app).get('/medical-history/1');

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 1,
        diagnosis: 'Common Cold',
      })
    );
  });

  it('should return medical history by ID (patient accessing own record)', async () => {
    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        req.user = { id: 1, role: 'patient' as const };
        next();
      }
    );

    mockPatientService.getPatientById.mockImplementation(
      (id: number | 'me') => {
        return mockPatientRepo
          .findOne({
            where: { id: id === 'me' ? 1 : id },
            relations: ['medicalHistories'],
          })
          .then(
            (result: any) =>
              result || { ...mockPatient, medicalHistories: [] }
          );
      }
    );

    const patientMedicalHistory = {
      ...mockMedicalHistory,
      patient: { id: 1 }, // Patient accessing their own record
    };

    mockPatientRepo.findOne.mockImplementation((options: any) => {
      if (
        options &&
        options.where &&
        options.where.id === 1 &&
        options.relations &&
        options.relations.includes('medicalHistories')
      ) {
        return Promise.resolve({
          ...mockPatient,
          medicalHistories: [],
        });
      }
      return Promise.resolve(null);
    });

    mockMedicalHistoryRepo.findOne.mockResolvedValue(
      patientMedicalHistory
    );
    const response = await request(app).get('/medical-history/1');

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 1,
        diagnosis: 'Common Cold',
      })
    );
    expect(mockPatientRepo.findOne).toHaveBeenCalledWith({
      where: { id: 1 },
      relations: ['medicalHistories'],
    });
  });

  it("should return 403 when patient tries to access another patient's record", async () => {
    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        req.user = { id: 2, role: 'patient' as const }; // Different patient ID
        next();
      }
    );

    mockPatientService.getPatientById.mockResolvedValue({
      ...mockPatient,
      id: 1,
    });

    mockPatientRepo.findOne.mockResolvedValue({
      ...mockPatient,
      id: 2,
      medicalHistories: [],
    });

    mockMedicalHistoryRepo.findOne.mockResolvedValue(
      mockMedicalHistory
    );

    const response = await request(app).get('/medical-history/1');

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        code: 'ACCESS_DENIED',
        message: 'Access forbidden',
        status: 403,
      },
    });
    expect(mockPatientService.getPatientById).toHaveBeenCalledWith(
      1,
      { id: 2 }
    );
  });

  it('should return medical history by ID (staff role)', async () => {
    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        req.user = { id: 3, role: 'staff' as const };
        next();
      }
    );

    mockPatientService.getPatientById.mockResolvedValue({
      ...mockPatient,
      id: 3,
    });

    mockPatientService.getPatientById.mockImplementation(
      (id: number | 'me') => {
        // For this test, id should be 1 (from the medical history record)
        const patientId = id === 'me' ? 3 : id; // For 'me', it would be the user ID, otherwise the patient ID
        return mockPatientRepo
          .findOne({
            where: { id: patientId },
            relations: ['medicalHistories'],
          })
          .then(
            (result: any) =>
              result || {
                ...mockPatient,
                id: patientId,
                medicalHistories: [],
              }
          );
      }
    );

    mockPatientRepo.findOne.mockImplementation((options: any) => {
      if (
        options &&
        options.where &&
        options.where.id === 1 &&
        options.relations &&
        options.relations.includes('medicalHistories')
      ) {
        return Promise.resolve({
          ...mockPatient,
          id: 1,
          medicalHistories: [],
        });
      }
      return Promise.resolve(null);
    });

    mockMedicalHistoryRepo.findOne.mockResolvedValue(
      mockMedicalHistory
    );

    const response = await request(app).get('/medical-history/1');

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 1,
        diagnosis: 'Common Cold',
      })
    );
    expect(mockPatientRepo.findOne).toHaveBeenCalledWith({
      where: { id: 1 }, // Patient ID from medical history, not staff user ID
      relations: ['medicalHistories'],
    });
  });

  it('should return 404 when medical history is not found', async () => {
    mockMedicalHistoryRepo.findOne.mockResolvedValue(null);

    const response = await request(app).get('/medical-history/999');

    expect(response.status).toBe(404);
    expect(response.body).toEqual({
      error: {
        code: 'NOT_FOUND',
        message: 'Medical history not found',
        status: 404,
      },
    });
  });

  it('should return 404 when patient is not found', async () => {
    mockMedicalHistoryRepo.findOne.mockResolvedValue(
      mockMedicalHistory
    );

    mockPatientService.getPatientById.mockResolvedValue(null);

    const response = await request(app).get('/medical-history/1');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'PATIENT_NOT_FOUND',
      message: 'Patient not found',
    });
    expect(mockPatientService.getPatientById).toHaveBeenCalledWith(
      1,
      { id: 1 }
    );
  });

  it('should handle errors in verifyMedicalHistoryAccess middleware', async () => {
    mockMedicalHistoryRepo.findOne.mockRejectedValue(
      new Error('Database error')
    );

    const response = await request(app).get('/medical-history/1');

    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      message: 'Database error',
    });
  });

  it('should return 400 for invalid medical history ID', async () => {
    const response = await request(app).get(
      '/medical-history/invalid'
    );

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        status: 400,
        code: 'INVALID_MEDICAL_HISTORY_ID',
        message: 'Invalid medical history ID',
      },
    });
  });
});
