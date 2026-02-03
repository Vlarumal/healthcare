import request from 'supertest';
import { createTestApp } from '../../../test-utils/appFactory';
import { resetMockServices, mockTokenService } from '../../../test-utils/mockServices';
import { UnauthorizedError } from '../../../errors/httpErrors';

// Mock services using the mock module
jest.mock('../../../services/tokenService', () => 
  require('../../../test-utils/mockServices').mockTokenServiceModule
);
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

describe('POST /logout', () => {
  let app: any;

  beforeEach(() => {
    resetMockServices();
    app = createTestApp();
  });

  it('should logout successfully and clear cookies', async () => {
    (mockTokenService.verifyRefreshToken as jest.Mock).mockResolvedValue({
      userId: 1,
      jti: 'token-id',
      exp: Math.floor(Date.now() / 1000) + 900,
      tokenVersion: process.env.TOKEN_VERSION,
    });
    (mockTokenService.revokeToken as jest.Mock).mockResolvedValue(true);

    const response = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', ['refreshToken=valid-refresh-token']);

    expect(response.status).toBe(204);
    expect(response.headers['set-cookie']).toBeDefined();
    expect(mockTokenService.verifyRefreshToken).toHaveBeenCalledWith(
      'valid-refresh-token'
    );
    expect(mockTokenService.revokeToken).toHaveBeenCalledWith(1, 'token-id');
  });

  it('should logout even with invalid refresh token', async () => {
    (mockTokenService.verifyRefreshToken as jest.Mock).mockRejectedValue(
      new UnauthorizedError('Invalid token')
    );

    const response = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', ['refreshToken=invalid-refresh-token']);

    expect(response.status).toBe(204);
    expect(response.headers['set-cookie']).toBeDefined();
    expect(mockTokenService.verifyRefreshToken).toHaveBeenCalledWith(
      'invalid-refresh-token'
    );
    expect(mockTokenService.revokeToken).not.toHaveBeenCalled();
  });

  it('should logout without refresh token', async () => {
    const response = await request(app).post('/api/auth/logout');

    expect(response.status).toBe(204);
    expect(response.headers['set-cookie']).toBeDefined();
    expect(mockTokenService.verifyRefreshToken).not.toHaveBeenCalled();
    expect(mockTokenService.revokeToken).not.toHaveBeenCalled();
  });
});
