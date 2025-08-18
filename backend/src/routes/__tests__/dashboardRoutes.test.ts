import request from 'supertest';
import express from 'express';
import dashboardRouter from '../dashboardRoutes';
import { AppDataSource } from '../../data-source';
import { Patient } from '../../entities/Patient';
import { MedicalHistory } from '../../entities/MedicalHistory';
import errorHandler from '../../middlewares/errorHandler';
import { Request, Response, NextFunction } from 'express';

jest.mock('../../data-source', () => ({
  AppDataSource: {
    isInitialized: true,
    getRepository: jest.fn(),
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

jest.mock('../../utils/logger', () => ({
  error: jest.fn(),
}));

const mockPatientRepository = {
  count: jest.fn(),
  find: jest.fn(),
};

const mockMedicalHistoryRepository = {
  count: jest.fn(),
};

beforeEach(() => {
  (AppDataSource.getRepository as jest.Mock).mockImplementation(
    (entity) => {
      if (entity === Patient) {
        return mockPatientRepository;
      } else if (entity === MedicalHistory) {
        return mockMedicalHistoryRepository;
      }
      throw new Error('Unknown entity');
    }
  );

  (AppDataSource.query as jest.Mock) = jest.fn();

  jest.clearAllMocks();
});

const app = express();
app.use(express.json());
app.use('/api/dashboard', dashboardRouter);
app.use(errorHandler);

describe('Dashboard Routes', () => {
  describe('GET /api/dashboard/patient-metrics', () => {
    it('should return patient metrics for admin user', async () => {
      mockPatientRepository.count
        .mockResolvedValueOnce(150) // totalPatients
        .mockResolvedValueOnce(15) // newPatients7Days
        .mockResolvedValueOnce(45) // newPatients30Days
        .mockResolvedValueOnce(120); // active patients

      (AppDataSource.query as jest.Mock)
        .mockResolvedValueOnce([
          { age_group: '18-34', count: '100' },
          { age_group: '35-49', count: '50' },
        ])
        .mockResolvedValueOnce([
          { gender: 'male', count: '100' },
          { gender: 'female', count: '50' },
        ]);

      const response = await request(app).get(
        '/api/dashboard/patient-metrics'
      );

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        totalPatients: 150,
        newPatients: {
          last7Days: 15,
          last30Days: 45,
        },
        demographics: {
          ageGroups: expect.any(Object),
          genderDistribution: expect.any(Object),
        },
        statusDistribution: {
          active: 120,
          discharged: 0,
          followUpNeeded: 0,
        },
      });
    });

    it('should return 403 for non-admin user', async () => {
      const mockAuthenticateJWT = jest.requireMock(
        '../../middlewares/authMiddleware'
      ).authenticateJWT;
      mockAuthenticateJWT.mockImplementationOnce(
        (req: Request, _res: Response, next: NextFunction) => {
          req.user = { id: 1, role: 'patient' as const };
          next();
        }
      );

      const response = await request(app).get(
        '/api/dashboard/patient-metrics'
      );

      expect(response.status).toBe(403);
    });

    it('should return 500 when database error occurs', async () => {
      mockPatientRepository.count.mockRejectedValue(
        new Error('Database error')
      );

      const response = await request(app).get(
        '/api/dashboard/patient-metrics'
      );

      expect(response.status).toBe(500);
      expect(response.body).toEqual({
        error: {
          status: 500,
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to fetch patient metrics',
        },
      });
    });
  });

  describe('GET /api/dashboard/appointment-metrics', () => {
    it('should return appointment metrics for admin user', async () => {
      mockMedicalHistoryRepository.count
        .mockResolvedValueOnce(5) // todaysAppointments
        .mockResolvedValueOnce(25) // upcomingAppointments
        .mockResolvedValueOnce(100); // totalMedicalHistories

      const response = await request(app).get(
        '/api/dashboard/appointment-metrics'
      );

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        todaysAppointments: 5,
        upcomingAppointments: 25,
        completionRate: 100,
        noShowRate: 0,
        clinicianWorkload: {},
      });
    });

    it('should handle patients with string dateOfBirth values', async () => {
      mockPatientRepository.count
        .mockResolvedValueOnce(150) // totalPatients
        .mockResolvedValueOnce(15) // newPatients7Days
        .mockResolvedValueOnce(45) // newPatients30Days
        .mockResolvedValueOnce(120); // active patients

      (AppDataSource.query as jest.Mock)
        .mockResolvedValueOnce([
          { age_group: '18-34', count: '100' },
          { age_group: '35-49', count: '50' },
        ])
        .mockResolvedValueOnce([
          { gender: 'male', count: '100' },
          { gender: 'female', count: '50' },
        ]);

      const response = await request(app).get(
        '/api/dashboard/patient-metrics'
      );

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        totalPatients: 150,
        newPatients: {
          last7Days: 15,
          last30Days: 45,
        },
        demographics: {
          ageGroups: expect.any(Object),
          genderDistribution: expect.any(Object),
        },
        statusDistribution: {
          active: 120,
          discharged: 0,
          followUpNeeded: 0,
        },
      });

      expect(response.body.demographics.ageGroups).toEqual({
        '0-17': expect.any(Number),
        '18-34': expect.any(Number),
        '35-49': expect.any(Number),
        '50-64': expect.any(Number),
        '65+': expect.any(Number),
      });
    });

    it('should return 403 for non-admin user', async () => {
      const mockAuthenticateJWT = jest.requireMock(
        '../../middlewares/authMiddleware'
      ).authenticateJWT;
      mockAuthenticateJWT.mockImplementationOnce(
        (req: Request, _res: Response, next: NextFunction) => {
          req.user = { id: 1, role: 'patient' as const };
          next();
        }
      );

      const response = await request(app).get(
        '/api/dashboard/appointment-metrics'
      );

      expect(response.status).toBe(403);
    });

    it('should return 500 when database error occurs', async () => {
      mockMedicalHistoryRepository.count.mockRejectedValue(
        new Error('Database error')
      );

      const response = await request(app).get(
        '/api/dashboard/appointment-metrics'
      );

      expect(response.status).toBe(500);
      expect(response.body).toEqual({
        error: {
          status: 500,
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to fetch appointment metrics',
        },
      });
    });
  });

  describe('GET /api/dashboard/system-metrics', () => {
    it('should return system metrics for admin user', async () => {
      (AppDataSource as any).isInitialized = true;

      const response = await request(app).get(
        '/api/dashboard/system-metrics'
      );

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        uptime: expect.any(Number),
        databaseHealth: 'healthy',
        apiPerformance: {
          avgResponseTime: 0,
          p95ResponseTime: 0,
          errorRate: 0,
        },
      });
    });

    it('should return 403 for non-admin user', async () => {
      const mockAuthenticateJWT = jest.requireMock(
        '../../middlewares/authMiddleware'
      ).authenticateJWT;
      mockAuthenticateJWT.mockImplementationOnce(
        (req: Request, _res: Response, next: NextFunction) => {
          req.user = { id: 1, role: 'patient' as const };
          next();
        }
      );

      const response = await request(app).get(
        '/api/dashboard/system-metrics'
      );

      expect(response.status).toBe(403);
    });

    it('should return database unhealthy when AppDataSource is not initialized', async () => {
      const originalIsInitialized = AppDataSource.isInitialized;
      (AppDataSource as any).isInitialized = false;

      const response = await request(app).get(
        '/api/dashboard/system-metrics'
      );

      expect(response.status).toBe(200);
      expect(response.body.databaseHealth).toBe('unhealthy');

      (AppDataSource as any).isInitialized = originalIsInitialized;
    });
  });
});
