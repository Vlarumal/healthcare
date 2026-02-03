import request from 'supertest';
import { AppDataSource } from '../../../../src/data-source';
import { Role } from '../../../types/auth';
import { createTestApp } from '../../../test-utils/appFactory';
import { mockRegularPatient } from '../../../test-utils/mockData';
import { resetMockServices } from '../../../test-utils/mockServices';

// Mock services
jest.mock('../../../services/tokenService', () => ({
  ...jest.requireActual('../../../test-utils/mockServices'),
  generateTokens: jest.fn(),
  storeRefreshToken: jest.fn(),
}));
jest.mock('../../../../src/data-source');
jest.mock('../../../middlewares/authMiddleware', () => ({
  authenticateJWT: jest.fn((req: any, _res: any, next: any) => {
    // Mock the middleware to set req.user and call next
    req.user = { id: mockRegularPatient.id, role: Role.PATIENT };
    next();
  }),
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

describe('GET /me', () => {
  let app: any;

  beforeEach(() => {
    resetMockServices();
    app = createTestApp();
  });

  it('should return user data for authenticated user', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue({
        ...mockRegularPatient,
        medicalHistories: [],
      }),
    });

    const response = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer valid-access-token');

    expect(response.status).toBe(200);
    // Response includes all patient fields except password and passwordVersion
    expect(response.body.id).toBe(mockRegularPatient.id);
    expect(response.body.firstName).toBe(mockRegularPatient.firstName);
    expect(response.body.lastName).toBe(mockRegularPatient.lastName);
    expect(response.body.email).toBe(mockRegularPatient.email);
    expect(response.body.dateOfBirth).toBe('1990-01-01');
    expect(response.body.role).toBe(Role.PATIENT);
  });

  it('should return 404 for non-existent user', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(null),
    });

    const response = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer valid-access-token');

    expect(response.status).toBe(404);
    expect(response.body).toEqual({
      error: {
        code: 'USER_NOT_FOUND',
        message: 'User not found',
        status: 404,
      },
    });
  });

  it('should handle database errors gracefully', async () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockRejectedValue(new Error('Database error')),
    });

    const response = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer valid-access-token');

    expect(response.status).toBe(500);

    consoleErrorSpy.mockRestore();
  });
});
