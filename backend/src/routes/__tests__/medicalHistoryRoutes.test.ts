import request from 'supertest';
import express from 'express';
import medicalHistoryRouter from '../medicalHistoryRoutes';
import { AppDataSource } from '../../index';
import { MedicalHistory } from '../../entities/MedicalHistory';
import { Patient } from '../../entities/Patient';
import { AuditLog } from '../../entities/AuditLog';
import errorHandler from '../../middlewares/errorHandler';
import { authenticateJWT } from '../../middlewares/authMiddleware';
import { Request, Response, NextFunction } from 'express';

jest.mock('../../index', () => ({
  AppDataSource: {
    getRepository: jest.fn(),
    isInitialized: true,
  },
}));

jest.mock('../../middlewares/authMiddleware', () => ({
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

jest.mock('../patientRoutes', () => {
  const actual = jest.requireActual('../patientRoutes');
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
  findOne: jest.fn(),
  findOneBy: jest.fn(),
  find: jest.fn(),
  delete: jest.fn(),
};

const mockPatientRepo = {
  findOneBy: jest.fn(),
  findOne: jest.fn(),
};

const mockAuditLogRepo = {
  save: jest.fn(),
};

(AppDataSource.getRepository as jest.Mock).mockImplementation(
  (entity) => {
    if (entity === MedicalHistory) return mockMedicalHistoryRepo;
    if (entity === Patient) return mockPatientRepo;
    if (entity === AuditLog) return mockAuditLogRepo;
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

describe('Medical History Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    // Reset the patientService singleton between tests
    const { resetPatientService } = jest.requireActual(
      '../patientRoutes'
    );
    resetPatientService();

    (authenticateJWT as jest.Mock).mockImplementation(
      (req: Request, _res: Response, next: NextFunction) => {
        if (!req.user) {
          req.user = { id: 1, role: 'admin' as const };
        }
        next();
      }
    );
  });

  describe('POST /medical-history', () => {
    const validMedicalHistoryData = {
      date: '2023-01-01',
      diagnosis: 'Common Cold',
      treatment: 'Rest and fluids',
      patientId: 1,
      notes: 'Patient recovering well',
    };

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

  describe('GET /medical-history/:id', () => {
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

  describe('GET /medical-history/patient/:patientId', () => {
    it('should return medical history records for a patient (admin role)', async () => {
      mockMedicalHistoryRepo.find.mockResolvedValue([
        mockMedicalHistory,
      ]);

      const response = await request(app).get(
        '/medical-history/patient/1'
      );

      expect(response.status).toBe(200);
      expect(response.body).toEqual([
        expect.objectContaining({
          id: 1,
          diagnosis: 'Common Cold',
        }),
      ]);
      expect(mockMedicalHistoryRepo.find).toHaveBeenCalledWith({
        where: { patient: { id: 1 } },
        relations: ['patient'],
        order: { date: 'DESC' },
      });
    });

    it('should return medical history records for a patient (clinician role)', async () => {
      (authenticateJWT as jest.Mock).mockImplementation(
        (req: Request, _res: Response, next: NextFunction) => {
          req.user = { id: 2, role: 'clinician' as const };
          next();
        }
      );

      mockMedicalHistoryRepo.find.mockResolvedValue([
        mockMedicalHistory,
      ]);

      const response = await request(app).get(
        '/medical-history/patient/1'
      );

      expect(response.status).toBe(200);
      expect(response.body).toEqual([
        expect.objectContaining({
          id: 1,
          diagnosis: 'Common Cold',
        }),
      ]);
    });

    it('should return medical history records for a patient (patient accessing own records)', async () => {
      (authenticateJWT as jest.Mock).mockImplementation(
        (req: Request, _res: Response, next: NextFunction) => {
          req.user = { id: 1, role: 'patient' as const };
          next();
        }
      );

      mockMedicalHistoryRepo.find.mockResolvedValue([
        mockMedicalHistory,
      ]);

      const response = await request(app).get(
        '/medical-history/patient/1'
      );

      expect(response.status).toBe(200);
      expect(response.body).toEqual([
        expect.objectContaining({
          id: 1,
          diagnosis: 'Common Cold',
        }),
      ]);
    });

    it('should return medical history records for a patient (staff role)', async () => {
      (authenticateJWT as jest.Mock).mockImplementation(
        (req: Request, _res: Response, next: NextFunction) => {
          req.user = { id: 3, role: 'staff' as const };
          next();
        }
      );

      mockMedicalHistoryRepo.find.mockResolvedValue([
        mockMedicalHistory,
      ]);

      const response = await request(app).get(
        '/medical-history/patient/1'
      );

      expect(response.status).toBe(200);
      expect(response.body).toEqual([
        expect.objectContaining({
          id: 1,
          diagnosis: 'Common Cold',
        }),
      ]);
    });
  });

  describe('PUT /medical-history/:id', () => {
    const validUpdateData = {
      diagnosis: 'Updated Diagnosis',
      treatment: 'Updated Treatment',
      notes: 'Updated notes',
    };

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

  describe('DELETE /medical-history/:id', () => {
    it('should delete a medical history record (admin role)', async () => {
      mockMedicalHistoryRepo.delete.mockResolvedValue({
        affected: 1,
      });

      const response = await request(app).delete(
        '/medical-history/1'
      );

      expect(response.status).toBe(204);
      expect(mockMedicalHistoryRepo.delete).toHaveBeenCalledWith(1);
    });

    it('should return 403 for clinician role', async () => {
      (authenticateJWT as jest.Mock).mockImplementation(
        (req: Request, _res: Response, next: NextFunction) => {
          req.user = { id: 2, role: 'clinician' as const };
          next();
        }
      );

      const response = await request(app).delete(
        '/medical-history/1'
      );

      expect(response.status).toBe(403);
      expect(response.body).toEqual({
        code: 'ACCESS_DENIED',
        message: 'Insufficient permissions for this operation',
      });
    });

    it('should return 403 for patient role', async () => {
      (authenticateJWT as jest.Mock).mockImplementation(
        (req: Request, _res: Response, next: NextFunction) => {
          req.user = { id: 1, role: 'patient' as const };
          next();
        }
      );

      const response = await request(app).delete(
        '/medical-history/1'
      );

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

      const response = await request(app).delete(
        '/medical-history/1'
      );

      expect(response.status).toBe(403);
      expect(response.body).toEqual({
        code: 'ACCESS_DENIED',
        message: 'Insufficient permissions for this operation',
      });
    });

    it('should return 404 when medical history is not found', async () => {
      mockMedicalHistoryRepo.delete.mockResolvedValue({
        affected: 0,
      });

      const response = await request(app).delete(
        '/medical-history/999'
      );

      expect(response.status).toBe(404);
      expect(response.body).toEqual({
        error: {
          code: 'NOT_FOUND',
          message: 'Medical history not found',
          status: 404,
        },
      });
    });
  });

  describe('Security and Edge Cases', () => {
    it('should reject requests without authentication', async () => {
      (authenticateJWT as jest.Mock).mockImplementation(
        (_req: Request, res: Response, _next: NextFunction) => {
          res.status(401).json({
            code: 'MISSING_TOKEN',
            message: 'Authorization token required',
          });
        }
      );

      const response = await request(app).get('/medical-history/1');

      expect(response.status).toBe(401);
      expect(response.body).toEqual({
        code: 'MISSING_TOKEN',
        message: 'Authorization token required',
      });
    });

    it('should properly handle empty notes field', async () => {
      const dataWithEmptyNotes = {
        date: '2023-01-01',
        diagnosis: 'Common Cold',
        treatment: 'Rest and fluids',
        patientId: 1,
        notes: '',
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
        .send(dataWithEmptyNotes);

      expect(response.status).toBe(201);
      expect(response.body.notes).toBe('');
    });

    it('should properly handle null notes field', async () => {
      const dataWithNullNotes = {
        date: '2023-01-01',
        diagnosis: 'Common Cold',
        treatment: 'Rest and fluids',
        patientId: 1,
        notes: null,
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
        .send(dataWithNullNotes);

      expect(response.status).toBe(201);
      expect(response.body.notes).toBe('');
    });

    it('should properly handle undefined notes field', async () => {
      const dataWithUndefinedNotes = {
        date: '2023-01-01',
        diagnosis: 'Common Cold',
        treatment: 'Rest and fluids',
        patientId: 1,
        // notes field is undefined
      };

      mockPatientRepo.findOneBy.mockResolvedValue(mockPatient);
      mockMedicalHistoryRepo.create.mockImplementation(
        (data) => data
      );
      mockMedicalHistoryRepo.save.mockResolvedValue({
        ...mockMedicalHistory,
        notes: undefined,
      });

      const response = await request(app)
        .post('/medical-history')
        .send(dataWithUndefinedNotes);

      expect(response.status).toBe(201);
    });
  });
});
