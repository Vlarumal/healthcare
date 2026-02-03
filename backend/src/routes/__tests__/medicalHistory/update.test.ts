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

const mockMedicalHistoryRepo = {
  findOneBy: jest.fn(),
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

describe('PUT /medical-history/:id', () => {
  const validUpdateData = {
    diagnosis: 'Updated Diagnosis',
    treatment: 'Updated Treatment',
    notes: 'Updated notes',
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

  it('should update a medical history record (admin role)', async () => {
    mockMedicalHistoryRepo.findOneBy.mockResolvedValue(
      mockMedicalHistory
    );
    mockMedicalHistoryRepo.save.mockResolvedValue({
      ...mockMedicalHistory,
      ...validUpdateData,
    });

    const response = await request(app)
      .put('/medical-history/1')
      .send(validUpdateData);

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 1,
        diagnosis: 'Updated Diagnosis',
        treatment: 'Updated Treatment',
      })
    );
    expect(mockMedicalHistoryRepo.findOneBy).toHaveBeenCalledWith({
      id: 1,
    });
    expect(mockMedicalHistoryRepo.save).toHaveBeenCalled();
  });

  it('should update a medical history record (clinician role)', async () => {
    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        req.user = { id: 2, role: 'clinician' as const };
        next();
      }
    );

    mockMedicalHistoryRepo.findOneBy.mockResolvedValue(
      mockMedicalHistory
    );
    mockMedicalHistoryRepo.save.mockResolvedValue({
      ...mockMedicalHistory,
      ...validUpdateData,
    });

    const response = await request(app)
      .put('/medical-history/1')
      .send(validUpdateData);

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        id: 1,
        diagnosis: 'Updated Diagnosis',
        treatment: 'Updated Treatment',
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
      .put('/medical-history/1')
      .send(validUpdateData);

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
      .put('/medical-history/1')
      .send(validUpdateData);

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      code: 'ACCESS_DENIED',
      message: 'Insufficient permissions for this operation',
    });
  });

  it('should return 400 for invalid input data', async () => {
    const invalidData = {
      diagnosis: 'A', // Too short
      treatment: 'B', // Too short
    };

    const response = await request(app)
      .put('/medical-history/1')
      .send(invalidData);

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        status: 400,
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        details: {
          errors: expect.arrayContaining([
            expect.objectContaining({ field: 'diagnosis' }),
            expect.objectContaining({ field: 'treatment' }),
          ]),
        },
      },
    });
  });

  it('should return 404 when medical history is not found', async () => {
    mockMedicalHistoryRepo.findOneBy.mockResolvedValue(null);

    const response = await request(app)
      .put('/medical-history/999')
      .send(validUpdateData);

    expect(response.status).toBe(404);
    expect(response.body).toEqual({
      error: {
        code: 'NOT_FOUND',
        message: 'Medical history not found',
        status: 404,
      },
    });
  });

  it('should sanitize XSS in notes field during update', async () => {
    const xssData = {
      ...validUpdateData,
      notes: '<script>alert("xss")</script>',
    };

    mockMedicalHistoryRepo.findOneBy.mockResolvedValue(
      mockMedicalHistory
    );
    mockMedicalHistoryRepo.save.mockResolvedValue({
      ...mockMedicalHistory,
      ...validUpdateData,
      notes: '',
    });

    const response = await request(app)
      .put('/medical-history/1')
      .send(xssData);

    expect(response.status).toBe(200);
    expect(response.body.notes).toBe('');
  });

  it('should handle patient reassignment during update', async () => {
    const updateDataWithPatient = {
      ...validUpdateData,
      patientId: 2,
    };

    const newPatient = {
      id: 2,
      firstName: 'Jane',
      lastName: 'Smith',
      email: 'jane.smith@example.com',
    };

    mockMedicalHistoryRepo.findOneBy.mockResolvedValue(
      mockMedicalHistory
    );
    mockPatientRepo.findOneBy.mockResolvedValue(newPatient);
    mockMedicalHistoryRepo.save.mockResolvedValue({
      ...mockMedicalHistory,
      ...validUpdateData,
      patient: newPatient,
    });

    const response = await request(app)
      .put('/medical-history/1')
      .send(updateDataWithPatient);

    expect(response.status).toBe(200);
    expect(response.body.patient.id).toBe(2);
    expect(mockPatientRepo.findOneBy).toHaveBeenCalledWith({
      id: 2,
    });
  });

  it('should return 404 when new patient is not found during update', async () => {
    const updateDataWithPatient = {
      ...validUpdateData,
      patientId: 999,
    };

    mockMedicalHistoryRepo.findOneBy.mockResolvedValue(
      mockMedicalHistory
    );
    mockPatientRepo.findOneBy.mockResolvedValue(null);

    const response = await request(app)
      .put('/medical-history/1')
      .send(updateDataWithPatient);

    expect(response.status).toBe(404);
    expect(response.body).toEqual({
      error: {
        code: 'PATIENT_NOT_FOUND',
        message: 'Patient not found',
        status: 404,
      },
    });
  });

  it('should handle null notes in update by setting to empty string', async () => {
    const updateDataWithNullNotes = {
      diagnosis: 'Updated Diagnosis',
      treatment: 'Updated Treatment',
      notes: null,
    };

    mockMedicalHistoryRepo.findOneBy.mockResolvedValue(
      mockMedicalHistory
    );
    mockMedicalHistoryRepo.save.mockResolvedValue({
      ...mockMedicalHistory,
      diagnosis: 'Updated Diagnosis',
      treatment: 'Updated Treatment',
      notes: '',
    });

    const response = await request(app)
      .put('/medical-history/1')
      .send(updateDataWithNullNotes);

    expect(response.status).toBe(200);
    expect(response.body.notes).toBe('');
    expect(mockMedicalHistoryRepo.save).toHaveBeenCalledWith(
      expect.objectContaining({
        notes: '',
      })
    );
  });

  it('should handle undefined notes in update by setting to empty string', async () => {
    const updateDataWithUndefinedNotes = {
      diagnosis: 'Updated Diagnosis',
      treatment: 'Updated Treatment',
      // notes field is undefined
    };

    mockMedicalHistoryRepo.findOneBy.mockResolvedValue(
      mockMedicalHistory
    );
    mockMedicalHistoryRepo.save.mockResolvedValue({
      ...mockMedicalHistory,
      diagnosis: 'Updated Diagnosis',
      treatment: 'Updated Treatment',
      notes: '',
    });

    const response = await request(app)
      .put('/medical-history/1')
      .send(updateDataWithUndefinedNotes);

    expect(response.status).toBe(200);
    expect(response.body.notes).toBe('');
    expect(mockMedicalHistoryRepo.save).toHaveBeenCalledWith(
      expect.objectContaining({
        notes: '',
      })
    );
  });
});
