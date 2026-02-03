import request from 'supertest';
import { AppDataSource } from '../../../data-source';
import { createTestApp } from '../../../test-utils/appFactory';
import { mockRegularPatient } from '../../../test-utils/mockData';
import { resetMockServices } from '../../../test-utils/mockServices';
import { setPasswordServiceInstance } from '../../authRoutes';
import { setTemporaryPassword } from '../../../utils/tempPasswordUtils';

// Mock services
jest.mock('../../../services/tokenService', () => ({
  ...jest.requireActual('../../../test-utils/mockServices'),
  generateTokens: jest.fn(),
  storeRefreshToken: jest.fn(),
}));
jest.mock('bcrypt');
jest.mock('../../../data-source');
jest.mock('../../../middlewares/authMiddleware', () => ({
  authenticateJWT: jest.fn((_req: any, _res: any, next: any) => next()),
  authorizeRole: jest.fn((_roles: any) => (_req: any, _res: any, next: any) => next()),
}));
jest.mock('../../../middlewares/csrfMiddleware', () => ({
  doubleCsrfProtection: jest.fn((_req, _res, next) => next()),
  generateCsrfToken: jest.fn().mockReturnValue('mock-csrf-token'),
  createCsrfMiddleware: jest.fn().mockReturnValue({
    doubleCsrfProtection: jest.fn((_req, _res, next) => next()),
    generateCsrfToken: jest.fn().mockReturnValue('mock-csrf-token'),
  }),
}));
jest.mock('../../../utils/tempPasswordUtils');

describe('POST /reset-password', () => {
  let app: any;

  beforeEach(() => {
    resetMockServices();
    app = createTestApp();
  });

  it('should reset password successfully', async () => {
    const patientWithPassword = {
      ...mockRegularPatient,
      temporaryPassword: 'old-temp-password',
      resetRequired: true,
    };
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(patientWithPassword),
      save: jest.fn().mockResolvedValue({
        ...patientWithPassword,
        password: 'new-hashed-password',
        temporaryPassword: null,
        resetRequired: false,
        passwordVersion: 2,
      }),
    });

    const validatePasswordSpy = jest.fn();
    const hashPasswordSpy = jest.fn().mockResolvedValue('new-hashed-password');

    const mockPasswordService = {
      validatePassword: validatePasswordSpy,
      hashPassword: hashPasswordSpy,
      generateTemporaryPassword: jest.fn().mockReturnValue('temp-password'),
    };

    setPasswordServiceInstance(mockPasswordService as any);

    const response = await request(app)
      .post('/api/auth/reset-password')
      .send({
        email: mockRegularPatient.email,
        newPassword: 'NewPassword123!',
      });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      message: 'Password reset successful',
    });
    expect(validatePasswordSpy).toHaveBeenCalledWith('NewPassword123!');
    expect(hashPasswordSpy).toHaveBeenCalledWith('NewPassword123!');

    setPasswordServiceInstance(null);
  });

  it('should return 404 for non-existent user', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(null),
    });

    const response = await request(app)
      .post('/api/auth/reset-password')
      .send({
        email: 'nonexistent@test.com',
        newPassword: 'NewPassword123!',
      });

    expect(response.status).toBe(404);
    expect(response.body).toEqual({
      error: {
        code: 'USER_NOT_FOUND',
        message: 'User not found',
        status: 404,
      },
    });
  });
});

describe('POST /request-temp-password', () => {
  let app: any;

  beforeEach(() => {
    jest.clearAllMocks();
    resetMockServices();
    app = createTestApp();
  });

  it('should request temporary password successfully', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(mockRegularPatient),
    });
    (setTemporaryPassword as jest.Mock).mockResolvedValue({
      success: true,
    });

    const response = await request(app)
      .post('/api/auth/request-temp-password')
      .send({ email: mockRegularPatient.email });

    expect(response.status).toBe(202);
    expect(response.body).toEqual({
      message:
        'If the email is registered, a temporary password will be sent shortly',
    });
    expect(setTemporaryPassword).toHaveBeenCalledWith(
      mockRegularPatient.email
    );
  });

  it('should return 202 immediately with success message for any valid email', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn(),
    });

    const response = await request(app)
      .post('/api/auth/request-temp-password')
      .send({ email: 'any@test.com' });

    expect(response.status).toBe(202);
    expect(response.body).toEqual({
      message:
        'If the email is registered, a temporary password will be sent shortly',
    });
  });

  it('should process temporary password in background for existing users', async () => {
    const findOneMock = jest.fn().mockResolvedValue(mockRegularPatient);
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: findOneMock,
    });
    (setTemporaryPassword as jest.Mock).mockResolvedValue({});

    const response = await request(app)
      .post('/api/auth/request-temp-password')
      .send({ email: mockRegularPatient.email });

    expect(response.status).toBe(202);

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(findOneMock).toHaveBeenCalledWith({
      where: { email: mockRegularPatient.email },
    });
    expect(setTemporaryPassword).toHaveBeenCalledWith(
      mockRegularPatient.email
    );
  });

  it('should not process temporary password for non-existent users', async () => {
    const findOneMock = jest.fn().mockResolvedValue(null);
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: findOneMock,
    });

    const response = await request(app)
      .post('/api/auth/request-temp-password')
      .send({ email: 'nonexistent@test.com' });

    expect(response.status).toBe(202);

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(findOneMock).toHaveBeenCalledWith({
      where: { email: 'nonexistent@test.com' },
    });
    expect(setTemporaryPassword).not.toHaveBeenCalled();
  });

  it('should return 400 for missing email', async () => {
    const response = await request(app)
      .post('/api/auth/request-temp-password')
      .send({});

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        status: 400,
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        details: {
          errors: [
            {
              field: 'email',
              message: 'Email is required',
            },
          ],
        },
      },
    });
  });
});
