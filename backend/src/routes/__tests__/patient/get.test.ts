import request from 'supertest';
import express from 'express';
import patientRouter from '../../patientRoutes';
import { PatientService } from '../../../services/PatientService';
import { authorizeRole } from '../../../middlewares/authMiddleware';
import { Response, NextFunction } from 'express';

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

interface MockPatientService {
  getPatients: jest.Mock;
  getPatientById: jest.Mock;
}

let mockPatientService: MockPatientService;

beforeEach(() => {
  mockPatientService = {
    getPatients: jest
      .fn()
      .mockResolvedValue({ data: [], total: 0 }),
    getPatientById: jest.fn().mockResolvedValue({
      id: 1,
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
    }),
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

describe('GET /patients', () => {
  it('should return 500 if database is not initialized in GET /patients endpoint', async () => {
    const mockAppDataSource =
      jest.requireMock('../../../index').AppDataSource;
    const originalIsInitialized = mockAppDataSource.isInitialized;
    mockAppDataSource.isInitialized = false;

    const response = await request(app).get('/patients');

    expect(response.status).toBe(500);

    mockAppDataSource.isInitialized = originalIsInitialized;
  });

  it('should return 500 for unexpected errors', async () => {
    mockPatientService.getPatients.mockRejectedValue(
      new Error('Unexpected error')
    );

    const response = await request(app).get('/patients');

    expect(response.status).toBe(500);
  });
});

it('should return 500 if database is not initialized in GET /patients/me endpoint', async () => {
  const mockAppDataSource =
    jest.requireMock('../../../index').AppDataSource;
  const originalIsInitialized = mockAppDataSource.isInitialized;
  mockAppDataSource.isInitialized = false;

  const response = await request(app).get('/patients/me');

  expect(response.status).toBe(500);

  mockAppDataSource.isInitialized = originalIsInitialized;
});

describe('GET /patients/:id', () => {
  it('should return 500 for unexpected errors', async () => {
    mockPatientService.getPatientById.mockRejectedValue(
      new Error('Unexpected error')
    );

    const response = await request(app).get('/patients/1');

    expect(response.status).toBe(500);
  });
});
