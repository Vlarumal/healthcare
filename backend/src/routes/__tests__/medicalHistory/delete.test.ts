import request from 'supertest';
import express from 'express';
import errorHandler from '../../../middlewares/errorHandler';
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
  delete: jest.fn(),
};

(AppDataSource.getRepository as jest.Mock).mockImplementation(
  (entity) => {
    if (entity === MedicalHistory) return mockMedicalHistoryRepo;
    return null;
  }
);

const app = express();
app.use(express.json());
app.use('/medical-history', medicalHistoryRouter);
app.use(errorHandler);

describe('DELETE /medical-history/:id', () => {
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
