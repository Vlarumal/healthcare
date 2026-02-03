import { Request, Response, NextFunction } from 'express';
import { authorizeRole } from '../../authMiddleware';

describe('authorizeRole', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockRequest = {};
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    mockNext = jest.fn();
  });

  it('should call next() when user has required role', () => {
    mockRequest.user = {
      id: 1,
      role: 'admin',
    };

    const roleMiddleware = authorizeRole(['admin', 'clinician']);

    roleMiddleware(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();

    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

  it('should return 403 when user does not have required role', () => {
    mockRequest.user = {
      id: 1,
      role: 'patient',
    };

    const roleMiddleware = authorizeRole(['admin', 'clinician']);

    roleMiddleware(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockResponse.status).toHaveBeenCalledWith(403);
    expect(mockResponse.json).toHaveBeenCalledWith({
      code: 'ACCESS_DENIED',
      message: 'Insufficient permissions for this operation',
    });

    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should return 403 when user has no role defined', () => {
    mockRequest.user = {
      id: 1,
      role: undefined as any,
    };

    const roleMiddleware = authorizeRole(['admin', 'clinician']);

    roleMiddleware(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockResponse.status).toHaveBeenCalledWith(403);
    expect(mockResponse.json).toHaveBeenCalledWith({
      code: 'ACCESS_DENIED',
      message: 'Insufficient permissions for this operation',
    });

    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should return 403 when no user object is attached to request', () => {
    mockRequest.user = undefined;

    const roleMiddleware = authorizeRole(['admin', 'clinician']);

    roleMiddleware(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockResponse.status).toHaveBeenCalledWith(403);
    expect(mockResponse.json).toHaveBeenCalledWith({
      code: 'ACCESS_DENIED',
      message: 'Insufficient permissions for this operation',
    });

    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should call next() when user has clinician role', () => {
    mockRequest.user = {
      id: 1,
      role: 'clinician',
    };

    const roleMiddleware = authorizeRole(['admin', 'clinician']);

    roleMiddleware(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();

    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

  it('should call next() when user has staff role', () => {
    mockRequest.user = {
      id: 1,
      role: 'staff',
    };

    const roleMiddleware = authorizeRole(['admin', 'staff']);

    roleMiddleware(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();

    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });
});
