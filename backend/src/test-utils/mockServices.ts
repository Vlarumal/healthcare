/**
 * Mock Services
 * 
 * Provides Jest mock implementations for all backend services.
 * These mocks can be imported and used across test files.
 * @module test-utils/mockServices
 */

import { Repository, ObjectLiteral } from 'typeorm';
import { Patient, Role } from '../entities/Patient';
import { Token } from '../entities/Token';
import { AuditLog } from '../entities/AuditLog';
import { MedicalHistory } from '../entities/MedicalHistory';
import {
  mockAdminPatient,
  mockRegularPatient,
  mockRefreshToken,
  mockMedicalHistory1,
  mockAuditLogCreate,
} from './mockData';

// ============================================================================
// Mock Patient Service Factory
// ============================================================================

/**
 * Mock implementation of the PatientService factory
 * Returns an object with all PatientService methods as Jest mocks
 */
export const createMockPatientService = () => ({
  getAllowedRoles: jest.fn().mockResolvedValue([
    'patient',
    'staff',
    'admin',
    'clinician',
    'guest',
  ]),

  getPatients: jest.fn().mockResolvedValue({
    data: [mockAdminPatient, mockRegularPatient],
    pagination: {
      total: 2,
      page: 1,
      pageSize: 10,
      totalPages: 1,
    },
  }),

  getPatientById: jest.fn().mockImplementation((id: number | 'me', viewer: { id: number }) => {
    if (id === 'me' || id === viewer.id) {
      return Promise.resolve(mockRegularPatient);
    }
    if (id === 1) {
      return Promise.resolve(mockAdminPatient);
    }
    return Promise.resolve(null);
  }),

  createPatient: jest.fn().mockImplementation((data: any) => {
    const newPatient = {
      ...mockRegularPatient,
      id: 999,
      ...data,
      password: 'hashed_temp_password',
      resetRequired: true,
    };
    return Promise.resolve(newPatient as Patient);
  }),

  updatePatient: jest.fn().mockImplementation((id: number, data: any, _updatedBy: { id: number }) => {
    if (id === 1) {
      return Promise.resolve({ ...mockAdminPatient, ...data } as Patient);
    }
    if (id === 2) {
      return Promise.resolve({ ...mockRegularPatient, ...data } as Patient);
    }
    const { PatientNotFoundError } = require('../errors/patientErrors');
    return Promise.reject(new PatientNotFoundError());
  }),

  deletePatient: jest.fn().mockImplementation((id: number, _deletedBy: { id: number }) => {
    if (id === 1 || id === 2) {
      return Promise.resolve();
    }
    const { PatientNotFoundError } = require('../errors/patientErrors');
    return Promise.reject(new PatientNotFoundError());
  }),
});

/**
 * Pre-instantiated mock patient service for simple use cases
 */
export const mockPatientService = createMockPatientService();

// ============================================================================
// Mock Token Service
// ============================================================================

/**
 * Mock token payload returned by token service
 */
export interface MockTokenPayload {
  userId: number;
  role: Role;
  passwordVersion: number;
  tokenVersionHash: string;
  fingerprint: string;
  jti: string;
}

/**
 * Mock implementation of token service functions
 */
export const mockTokenService = {
  generateTokens: jest.fn().mockReturnValue({
    accessToken: 'mock-access-token',
    refreshToken: 'mock-refresh-token',
  }),

  verifyAccessToken: jest.fn().mockReturnValue({
    userId: mockRegularPatient.id,
    role: mockRegularPatient.role,
    passwordVersion: mockRegularPatient.passwordVersion,
    tokenVersionHash: 'mock-token-version-hash',
    fingerprint: 'mock-fingerprint-hash',
    jti: 'mock-jti-123',
  }),

  verifyRefreshToken: jest.fn().mockReturnValue({
    userId: mockRegularPatient.id,
    role: mockRegularPatient.role,
    passwordVersion: mockRegularPatient.passwordVersion,
    tokenVersionHash: 'mock-token-version-hash',
    fingerprint: 'mock-fingerprint-hash',
    jti: 'mock-jti-123',
  }),

  generateFingerprint: jest.fn().mockReturnValue('mock-fingerprint-hash'),

  storeRefreshToken: jest.fn().mockResolvedValue(undefined),

  rotateRefreshToken: jest.fn().mockResolvedValue({
    accessToken: 'new-mock-access-token',
    refreshToken: 'new-mock-refresh-token',
  }),

  revokeToken: jest.fn().mockResolvedValue(undefined),

  revokeAllTokensForUser: jest.fn().mockResolvedValue(undefined),
};

// ============================================================================
// Mock Audit Service
// ============================================================================

/**
 * Mock implementation of AuditService class
 */
export class MockAuditService {
  logPatientAction = jest.fn().mockResolvedValue(undefined);
  logError = jest.fn().mockResolvedValue(undefined);
}

/**
 * Pre-instantiated mock audit service
 */
export const mockAuditService = new MockAuditService();

// ============================================================================
// Mock Email Service
// ============================================================================

/**
 * Mock implementation of EmailService class
 */
export class MockEmailService {
  sendTemporaryPasswordEmail = jest.fn().mockResolvedValue(undefined);
  sendVerificationEmail = jest.fn().mockResolvedValue(undefined);
}

/**
 * Pre-instantiated mock email service
 */
export const mockEmailService = new MockEmailService();

/**
 * Standalone mock email functions (for direct imports)
 */
export const sendTemporaryPasswordEmail = jest.fn().mockImplementation((email: string, _password: string) => {
  console.log(`Mock: Sending temporary password to ${email}`);
  return Promise.resolve();
});

export const sendPasswordResetEmail = jest.fn().mockResolvedValue(undefined);
export const sendAccountActivationEmail = jest.fn().mockResolvedValue(undefined);

// ============================================================================
// Mock Password Service
// ============================================================================

/**
 * Mock implementation of PasswordService class
 */
export class MockPasswordService {
  generateTemporaryPassword = jest.fn().mockReturnValue('TempPass123!');
  hashPassword = jest.fn().mockResolvedValue('hashed_password_mock');
  validatePassword = jest.fn().mockImplementation((_password: string) => {
    // Mock validation - doesn't throw for any password in tests unless configured
  });
}

/**
 * Pre-instantiated mock password service
 */
export const mockPasswordService = new MockPasswordService();

// ============================================================================
// Mock Database Repositories
// ============================================================================

/**
 * Creates a mock TypeORM repository for testing
 */
export function createMockRepository<T extends ObjectLiteral>(mockData?: T[]): Repository<T> {
  const data = mockData || [];
  
  return {
    find: jest.fn().mockResolvedValue(data),
    findOne: jest.fn().mockImplementation((options: any) => {
      if (options?.where?.id && Array.isArray(data)) {
        return Promise.resolve(data.find((item: any) => item.id === options.where.id) || null);
      }
      return Promise.resolve(data[0] || null);
    }),
    findOneBy: jest.fn().mockImplementation((criteria: any) => {
      if (criteria?.id && Array.isArray(data)) {
        return Promise.resolve(data.find((item: any) => item.id === criteria.id) || null);
      }
      return Promise.resolve(data[0] || null);
    }),
    save: jest.fn().mockImplementation((entity: any) => {
      if (Array.isArray(entity)) {
        return Promise.resolve(entity.map((e, i) => ({ ...e, id: e.id || i + 1 })));
      }
      return Promise.resolve({ ...entity, id: entity.id || 999 });
    }),
    create: jest.fn().mockImplementation((entity: any) => entity),
    update: jest.fn().mockResolvedValue({ affected: 1 }),
    delete: jest.fn().mockResolvedValue({ affected: 1 }),
    softDelete: jest.fn().mockResolvedValue({ affected: 1 }),
    remove: jest.fn().mockImplementation((entity: any) => Promise.resolve(entity)),
    createQueryBuilder: jest.fn().mockReturnValue({
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      addSelect: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      addOrderBy: jest.fn().mockReturnThis(),
      offset: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      skip: jest.fn().mockReturnThis(),
      take: jest.fn().mockReturnThis(),
      innerJoin: jest.fn().mockReturnThis(),
      leftJoin: jest.fn().mockReturnThis(),
      leftJoinAndSelect: jest.fn().mockReturnThis(),
      getMany: jest.fn().mockResolvedValue(data),
      getManyAndCount: jest.fn().mockResolvedValue([data, data.length]),
      getOne: jest.fn().mockResolvedValue(data[0] || null),
      getRawMany: jest.fn().mockResolvedValue([]),
      getRawOne: jest.fn().mockResolvedValue(null),
      execute: jest.fn().mockResolvedValue(undefined),
    }),
    count: jest.fn().mockResolvedValue(data.length),
    countBy: jest.fn().mockResolvedValue(data.length),
    exists: jest.fn().mockResolvedValue(data.length > 0),
    existsBy: jest.fn().mockResolvedValue(data.length > 0),
    clear: jest.fn().mockResolvedValue(undefined),
    increment: jest.fn().mockResolvedValue({ affected: 1 }),
    decrement: jest.fn().mockResolvedValue({ affected: 1 }),
    query: jest.fn().mockResolvedValue([]),
  } as unknown as Repository<T>;
}

/**
 * Pre-configured mock repositories for common entities
 */
export const mockPatientRepository = createMockRepository<Patient>([mockAdminPatient, mockRegularPatient]);
export const mockTokenRepository = createMockRepository<Token>([mockRefreshToken]);
export const mockAuditLogRepository = createMockRepository<AuditLog>([mockAuditLogCreate]);
export const mockMedicalHistoryRepository = createMockRepository<MedicalHistory>([mockMedicalHistory1]);

// ============================================================================
// Jest Module Mocks Setup
// ============================================================================

/**
 * Mock implementation map for jest.mock() usage
 * 
 * Usage in test files:
 * ```typescript
 * jest.mock('../services/tokenService', () => mockTokenServiceModule);
 * ```
 */
export const mockTokenServiceModule = {
  generateTokens: mockTokenService.generateTokens,
  verifyAccessToken: mockTokenService.verifyAccessToken,
  verifyRefreshToken: mockTokenService.verifyRefreshToken,
  generateFingerprint: mockTokenService.generateFingerprint,
  storeRefreshToken: mockTokenService.storeRefreshToken,
  rotateRefreshToken: mockTokenService.rotateRefreshToken,
  revokeToken: mockTokenService.revokeToken,
  revokeAllTokensForUser: mockTokenService.revokeAllTokensForUser,
};

/**
 * Mock implementation map for AuditService module
 */
export const mockAuditServiceModule = {
  AuditService: MockAuditService,
};

/**
 * Mock implementation map for emailService module
 */
export const mockEmailServiceModule = {
  EmailService: MockEmailService,
  sendTemporaryPasswordEmail,
  sendPasswordResetEmail,
  sendAccountActivationEmail,
};

/**
 * Mock implementation map for passwordService module
 */
export const mockPasswordServiceModule = {
  PasswordService: MockPasswordService,
};

// ============================================================================
// Service Reset Helpers
// ============================================================================

/**
 * Reset all mock service implementations to their default state
 * Call this in beforeEach to ensure test isolation
 */
export function resetMockServices(): void {
  // Reset Patient Service
  Object.values(mockPatientService).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockClear();
    }
  });

  // Reset Token Service
  Object.values(mockTokenService).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockClear();
    }
  });

  // Reset Audit Service
  mockAuditService.logPatientAction.mockClear();
  mockAuditService.logError.mockClear();

  // Reset Email Service
  mockEmailService.sendTemporaryPasswordEmail.mockClear();
  mockEmailService.sendVerificationEmail.mockClear();

  // Reset Password Service
  mockPasswordService.generateTemporaryPassword.mockClear();
  mockPasswordService.hashPassword.mockClear();
  mockPasswordService.validatePassword.mockClear();

  // Reset standalone email functions
  sendTemporaryPasswordEmail.mockClear();
  sendPasswordResetEmail.mockClear();
  sendAccountActivationEmail.mockClear();
}

/**
 * Configure mock patient service for specific test scenarios
 */
export function configureMockPatientService(scenario: 'success' | 'notFound' | 'error'): void {
  const { PatientNotFoundError } = require('../errors/patientErrors');
  
  switch (scenario) {
    case 'success':
      mockPatientService.getPatientById.mockResolvedValue(mockRegularPatient);
      mockPatientService.createPatient.mockResolvedValue(mockRegularPatient);
      mockPatientService.updatePatient.mockResolvedValue(mockRegularPatient);
      mockPatientService.deletePatient.mockResolvedValue(undefined);
      break;
    
    case 'notFound':
      mockPatientService.getPatientById.mockResolvedValue(null);
      mockPatientService.updatePatient.mockRejectedValue(new PatientNotFoundError());
      mockPatientService.deletePatient.mockRejectedValue(new PatientNotFoundError());
      break;
    
    case 'error':
      const error = new Error('Database error');
      mockPatientService.getPatientById.mockRejectedValue(error);
      mockPatientService.createPatient.mockRejectedValue(error);
      mockPatientService.updatePatient.mockRejectedValue(error);
      mockPatientService.deletePatient.mockRejectedValue(error);
      break;
  }
}

/**
 * Configure mock token service for authentication scenarios
 */
export function configureMockTokenService(scenario: 'valid' | 'expired' | 'invalid'): void {
  const { InvalidTokenError } = require('../errors/authErrors');
  
  switch (scenario) {
    case 'valid':
      mockTokenService.verifyAccessToken.mockReturnValue({
        userId: mockRegularPatient.id,
        role: mockRegularPatient.role,
        passwordVersion: mockRegularPatient.passwordVersion,
        tokenVersionHash: 'mock-token-version-hash',
        fingerprint: 'mock-fingerprint-hash',
        jti: 'mock-jti-123',
      });
      mockTokenService.verifyRefreshToken.mockReturnValue({
        userId: mockRegularPatient.id,
        role: mockRegularPatient.role,
        passwordVersion: mockRegularPatient.passwordVersion,
        tokenVersionHash: 'mock-token-version-hash',
        fingerprint: 'mock-fingerprint-hash',
        jti: 'mock-jti-123',
      });
      break;
    
    case 'expired':
      const expiredError = new InvalidTokenError('Token has expired');
      mockTokenService.verifyAccessToken.mockImplementation(() => {
        throw expiredError;
      });
      mockTokenService.verifyRefreshToken.mockImplementation(() => {
        throw expiredError;
      });
      break;
    
    case 'invalid':
      const invalidError = new InvalidTokenError('Invalid token');
      mockTokenService.verifyAccessToken.mockImplementation(() => {
        throw invalidError;
      });
      mockTokenService.verifyRefreshToken.mockImplementation(() => {
        throw invalidError;
      });
      break;
  }
}

// ============================================================================
// Type Exports
// ============================================================================

/**
 * Type for the mock patient service returned by createMockPatientService
 */
export type MockPatientServiceType = ReturnType<typeof createMockPatientService>;

/**
 * Type for the mock token service
 */
export type MockTokenServiceType = typeof mockTokenService;
