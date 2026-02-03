import request from 'supertest';
import express from 'express';
import medicalHistoryRouter from '../../medicalHistoryRoutes';
import { AppDataSource } from '../../../index';
import { MedicalHistory } from '../../../entities/MedicalHistory';
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
  find: jest.fn(),
};

(AppDataSource.getRepository as jest.Mock).mockImplementation(
  (entity) => {
    if (entity === MedicalHistory) return mockMedicalHistoryRepo;
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

describe('GET /medical-history/patient/:patientId', () => {
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
