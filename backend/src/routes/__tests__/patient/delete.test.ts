import request from 'supertest';
import express from 'express';
import patientRouter from '../../patientRoutes';
import { PatientService } from '../../../services/PatientService';
import { AuditService } from '../../../services/AuditService';
import { authorizeRole } from '../../../middlewares/authMiddleware';
import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../../../types/express.d';

// Mock services
jest.mock('../../../services/PatientService', () => ({
  PatientService: jest.fn(),
  resetPatientService: jest.fn(),
}));

jest.mock('../../../services/AuditService', () => ({
  AuditService: jest.fn(),
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
  deletePatient: jest.Mock;
}

interface MockAuditService {
  logPatientAction: jest.Mock;
}

let mockPatientService: MockPatientService;
let mockAuditService: MockAuditService;

beforeEach(() => {
  mockPatientService = {
    deletePatient: jest.fn().mockResolvedValue(true),
  };

  mockAuditService = {
    logPatientAction: jest.fn().mockResolvedValue(undefined),
  };

  (PatientService as jest.Mock).mockImplementation(
    () => mockPatientService
  );
  (AuditService as jest.Mock).mockImplementation(
    () => mockAuditService
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

describe('DELETE /patients/:id', () => {
  it('should prevent patient from deleting any record', async () => {
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

    const response = await request(app).delete('/patients/1');

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      code: 'ACCESS_DENIED',
      message: 'Insufficient permissions for this operation',
    });
  });

  it('should return 403 for non-admin roles', async () => {
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
        }; // Patient role is not authorized for DELETE /patients/:id
        next();
      }
    );

    mockPatientService.deletePatient.mockImplementationOnce(() => {
      throw new Error('Should not be called');
    });

    const response = await request(app).delete('/patients/1');
    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      code: 'ACCESS_DENIED',
      message: 'Insufficient permissions for this operation',
    });
    expect(mockPatientService.deletePatient).not.toHaveBeenCalled();
    expect(mockAuditService.logPatientAction).not.toHaveBeenCalled();
  });

  it('should return 500 for unexpected errors', async () => {
    const mockAuthenticateJWT = jest.requireMock(
      '../../../middlewares/authMiddleware'
    ).authenticateJWT;
    mockAuthenticateJWT.mockImplementationOnce(
      (
        req: AuthenticatedRequest,
        _res: Response,
        next: NextFunction
      ) => {
        req.user = { id: 1, role: 'admin' as const, tokenVersion: 0 };
        next();
      }
    );

    mockPatientService.deletePatient.mockRejectedValue(
      new Error('Unexpected error')
    );

    const response = await request(app).delete('/patients/1');

    expect(response.status).toBe(500);
  });
});
