/**
 * Mock Data Utilities
 * 
 * Provides mock data objects for testing purposes.
 * All entities follow the database schema and TypeORM entity definitions.
 * @module test-utils/mockData
 */

import { Patient, Gender, Role } from '../entities/Patient';
import { MedicalHistory } from '../entities/MedicalHistory';
import { Token } from '../entities/Token';
import { AuditLog, AuditAction } from '../entities/AuditLog';

// ============================================================================
// Mock Patient Data
// ============================================================================

/**
 * Base mock patient template with common properties
 */
const baseMockPatient: Partial<Patient> = {
  dateOfBirth: new Date('1990-01-01'),
  gender: Gender.MALE,
  phoneNumber: '+1234567890',
  address: '123 Test St',
  city: 'Test City',
  zipCode: '12345',
  passwordVersion: 1,
  resetRequired: false,
  temporaryPassword: null,
  createdAt: new Date('2024-01-01'),
};

/**
 * Creates a mock Patient object with proper method bindings
 */
function createMockPatientObject(
  id: number,
  firstName: string,
  lastName: string,
  email: string,
  password: string,
  role: Role,
  gender: Gender = Gender.MALE
): Patient {
  const patient = {
    ...baseMockPatient,
    id,
    firstName,
    lastName,
    email,
    password,
    role,
    gender,
    medicalHistories: [],
    tokens: [],
    consents: [],
    auditLogs: [],
    toJSON(this: Patient) {
      const { password, temporaryPassword, passwordVersion, tokens, ...rest } = this;
      return {
        ...rest,
        dateOfBirth: this.dateOfBirth instanceof Date
          ? this.dateOfBirth.toISOString().split('T')[0]
          : this.dateOfBirth
      };
    },
    getAuditData(this: Patient) {
      return {
        firstName: this.firstName,
        lastName: this.lastName,
        email: this.email,
        role: this.role
      };
    },
  };
  return patient as unknown as Patient;
}

/**
 * Mock admin patient with administrative privileges
 */
export const mockAdminPatient: Patient = createMockPatientObject(
  1,
  'Admin',
  'User',
  'admin@test.com',
  'hashed_password_admin',
  Role.ADMIN
);

/**
 * Mock regular patient (default role)
 */
export const mockRegularPatient: Patient = createMockPatientObject(
  2,
  'John',
  'Doe',
  'john.doe@test.com',
  'hashed_password_regular',
  Role.PATIENT
);

/**
 * Mock guest patient with limited privileges
 */
export const mockGuestPatient: Patient = createMockPatientObject(
  3,
  'Guest',
  'User',
  'guest@test.com',
  'hashed_password_guest',
  Role.GUEST
);

/**
 * Mock staff patient
 */
export const mockStaffPatient: Patient = createMockPatientObject(
  4,
  'Staff',
  'Member',
  'staff@test.com',
  'hashed_password_staff',
  Role.STAFF,
  Gender.FEMALE
);

/**
 * Mock clinician patient
 */
export const mockClinicianPatient: Patient = createMockPatientObject(
  5,
  'Doctor',
  'Smith',
  'clinician@test.com',
  'hashed_password_clinician',
  Role.CLINICIAN,
  Gender.UNSPECIFIED
);

/**
 * Array of all mock patients for bulk operations
 */
export const mockPatients: Patient[] = [
  mockAdminPatient,
  mockRegularPatient,
  mockGuestPatient,
  mockStaffPatient,
  mockClinicianPatient,
];

// ============================================================================
// Mock Medical History Data
// ============================================================================

/**
 * Base mock medical history template
 */
const baseMockMedicalHistory: Partial<MedicalHistory> = {
  date: new Date('2024-01-15'),
  createdAt: new Date('2024-01-15'),
  updatedAt: new Date('2024-01-15'),
};

/**
 * Mock medical history for regular patient
 */
export const mockMedicalHistory1: MedicalHistory = {
  ...baseMockMedicalHistory,
  id: 1,
  diagnosis: 'Hypertension',
  treatment: 'Prescribed Lisinopril 10mg daily',
  notes: 'Patient advised to monitor blood pressure regularly',
  allergies: 'None known',
  patient: mockRegularPatient,
  patientId: mockRegularPatient.id,
} as MedicalHistory;

/**
 * Mock medical history with allergies
 */
export const mockMedicalHistory2: MedicalHistory = {
  ...baseMockMedicalHistory,
  id: 2,
  date: new Date('2024-02-20'),
  diagnosis: 'Seasonal Allergies',
  treatment: 'Antihistamines as needed',
  notes: 'Symptoms worse in spring',
  allergies: 'Pollen, Dust mites',
  patient: mockRegularPatient,
  patientId: mockRegularPatient.id,
} as MedicalHistory;

/**
 * Mock medical history for admin patient
 */
export const mockMedicalHistory3: MedicalHistory = {
  ...baseMockMedicalHistory,
  id: 3,
  date: new Date('2024-03-10'),
  diagnosis: 'Annual Physical',
  treatment: 'No treatment required',
  notes: 'All vitals normal',
  allergies: 'Penicillin',
  patient: mockAdminPatient,
  patientId: mockAdminPatient.id,
} as MedicalHistory;

/**
 * Array of all mock medical histories
 */
export const mockMedicalHistories: MedicalHistory[] = [
  mockMedicalHistory1,
  mockMedicalHistory2,
  mockMedicalHistory3,
];

// ============================================================================
// Mock Token Data
// ============================================================================

/**
 * Base mock token template
 */
const baseMockToken: Partial<Token> = {
  type: 'refresh',
  expiresAt: new Date('2025-01-01'),
  revoked: false,
};

/**
 * Mock refresh token for regular patient
 */
export const mockRefreshToken: Token = {
  ...baseMockToken,
  id: 1,
  token: 'mock-refresh-token-jti-1',
  patient: mockRegularPatient,
} as Token;

/**
 * Mock refresh token for admin
 */
export const mockAdminRefreshToken: Token = {
  ...baseMockToken,
  id: 2,
  token: 'mock-refresh-token-jti-2',
  patient: mockAdminPatient,
} as Token;

/**
 * Mock revoked token
 */
export const mockRevokedToken: Token = {
  ...baseMockToken,
  id: 3,
  token: 'mock-revoked-token-jti',
  revoked: true,
  patient: mockRegularPatient,
} as Token;

/**
 * Array of all mock tokens
 */
export const mockTokens: Token[] = [
  mockRefreshToken,
  mockAdminRefreshToken,
  mockRevokedToken,
];

// ============================================================================
// Mock User Objects for Auth Tests
// ============================================================================

/**
 * User object structure used in JWT tokens and auth context
 */
export interface MockAuthUser {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  role: Role;
  passwordVersion: number;
}

/**
 * Mock authenticated admin user
 */
export const mockAuthAdmin: MockAuthUser = {
  id: mockAdminPatient.id,
  email: mockAdminPatient.email,
  firstName: mockAdminPatient.firstName,
  lastName: mockAdminPatient.lastName,
  role: Role.ADMIN,
  passwordVersion: 1,
};

/**
 * Mock authenticated regular user
 */
export const mockAuthUser: MockAuthUser = {
  id: mockRegularPatient.id,
  email: mockRegularPatient.email,
  firstName: mockRegularPatient.firstName,
  lastName: mockRegularPatient.lastName,
  role: Role.PATIENT,
  passwordVersion: 1,
};

/**
 * Mock authenticated regular user (sanitized for login response)
 * This matches the expected response from POST /login
 */
export const mockAuthUserSanitized: MockAuthUser = {
  id: mockRegularPatient.id,
  email: mockRegularPatient.email,
  firstName: mockRegularPatient.firstName,
  lastName: mockRegularPatient.lastName,
  role: Role.PATIENT,
  passwordVersion: 1,
};

/**
 * Creates a mock patient object specifically for login response tests
 * Returns only essential user data (id, firstName, lastName, email, dateOfBirth, role)
 * when serialized to JSON, matching the original authRoutes.test.ts mockPatient
 */
export function createLoginMockPatient(
  id: number = 1,
  firstName: string = 'John',
  lastName: string = 'Doe',
  email: string = 'john.doe@example.com',
  role: Role = Role.PATIENT
): Patient {
  const patient = {
    id,
    firstName,
    lastName,
    email,
    password: 'hashed_password',
    dateOfBirth: new Date('1990-01-01'),
    role,
    passwordVersion: 1,
    temporaryPassword: null,
    resetRequired: false,
    // Additional properties that should be excluded from login response
    address: '123 Test St',
    city: 'Test City',
    zipCode: '12345',
    phoneNumber: '+1234567890',
    gender: Gender.MALE,
    medicalHistories: [],
    tokens: [],
    consents: [],
    auditLogs: [],
    createdAt: new Date('2024-01-01'),
    // This toJSON returns ONLY the fields expected by login tests
    toJSON(this: Patient) {
      return {
        id: this.id,
        firstName: this.firstName,
        lastName: this.lastName,
        email: this.email,
        dateOfBirth: this.dateOfBirth instanceof Date
          ? this.dateOfBirth.toISOString().split('T')[0]
          : this.dateOfBirth,
        role: this.role,
      };
    },
    getAuditData(this: Patient) {
      return {
        firstName: this.firstName,
        lastName: this.lastName,
        email: this.email,
        role: this.role
      };
    },
  };
  return patient as unknown as Patient;
}

/**
 * Mock patient for login tests - returns minimal fields when serialized
 */
export const mockLoginPatient: Patient = createLoginMockPatient();

/**
 * Mock authenticated staff user
 */
export const mockAuthStaff: MockAuthUser = {
  id: mockStaffPatient.id,
  email: mockStaffPatient.email,
  firstName: mockStaffPatient.firstName,
  lastName: mockStaffPatient.lastName,
  role: Role.STAFF,
  passwordVersion: 1,
};

/**
 * Mock authenticated clinician user
 */
export const mockAuthClinician: MockAuthUser = {
  id: mockClinicianPatient.id,
  email: mockClinicianPatient.email,
  firstName: mockClinicianPatient.firstName,
  lastName: mockClinicianPatient.lastName,
  role: Role.CLINICIAN,
  passwordVersion: 1,
};

// ============================================================================
// Mock Audit Log Data
// ============================================================================

/**
 * Base mock audit log template
 */
const baseMockAuditLog: Partial<AuditLog> = {
  action: AuditAction.VIEW_PATIENT,
  timestamp: new Date('2024-01-01T00:00:00Z'),
  details: {},
};

/**
 * Mock audit log for view patient action
 */
export const mockAuditLogView: AuditLog = {
  ...baseMockAuditLog,
  id: 1,
  patient: mockRegularPatient,
  performedById: mockRegularPatient.id,
} as AuditLog;

/**
 * Mock audit log for patient creation
 */
export const mockAuditLogCreate: AuditLog = {
  ...baseMockAuditLog,
  id: 2,
  action: AuditAction.CREATE_PATIENT,
  patient: mockRegularPatient,
  performedById: mockAdminPatient.id,
  details: { firstName: 'John', lastName: 'Doe' },
} as AuditLog;

/**
 * Mock audit log for patient update
 */
export const mockAuditLogUpdate: AuditLog = {
  ...baseMockAuditLog,
  id: 3,
  action: AuditAction.UPDATE_PATIENT,
  patient: mockRegularPatient,
  performedById: mockAdminPatient.id,
  details: { updatedFields: ['firstName', 'lastName'] },
} as AuditLog;

/**
 * Array of all mock audit logs
 */
export const mockAuditLogs: AuditLog[] = [
  mockAuditLogView,
  mockAuditLogCreate,
  mockAuditLogUpdate,
];

// ============================================================================
// Mock Request/Response Data
// ============================================================================

/**
 * Mock signup request body
 */
export const mockSignupRequest = {
  firstName: 'New',
  lastName: 'Patient',
  email: 'new.patient@test.com',
  password: 'SecurePass123!',
  dateOfBirth: '1990-05-15',
};

/**
 * Mock login request body
 */
export const mockLoginRequest = {
  email: 'john.doe@test.com',
  password: 'SecurePass123!',
};

/**
 * Mock create patient request (admin only)
 */
export const mockCreatePatientRequest = {
  firstName: 'Jane',
  lastName: 'Smith',
  email: 'jane.smith@test.com',
  dateOfBirth: '1985-03-20',
  gender: Gender.FEMALE,
  phoneNumber: '+1987654321',
};

/**
 * Mock update patient request
 */
export const mockUpdatePatientRequest = {
  firstName: 'John',
  lastName: 'Updated',
  email: 'john.updated@test.com',
};

/**
 * Mock create medical history request
 */
export const mockCreateMedicalHistoryRequest = {
  date: '2024-01-15',
  diagnosis: 'Test Diagnosis',
  treatment: 'Test Treatment',
  notes: 'Test notes',
  allergies: 'None',
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Creates a copy of a mock patient with specified overrides
 * 
 * @param basePatient - Base patient to copy
 * @param overrides - Properties to override
 * @returns New patient object with overrides applied
 */
export function createMockPatient(
  basePatient: Patient = mockRegularPatient,
  overrides: Partial<Patient> = {}
): Patient {
  const patient = {
    ...basePatient,
    ...overrides,
    // Reset relations to empty arrays unless explicitly provided
    medicalHistories: overrides.medicalHistories ?? [],
    tokens: overrides.tokens ?? [],
    consents: overrides.consents ?? [],
    auditLogs: overrides.auditLogs ?? [],
  };

  // Bind the methods to the new object
  const originalToJSON = basePatient.toJSON;
  const originalGetAuditData = basePatient.getAuditData;
  
  (patient as Patient).toJSON = originalToJSON.bind(patient);
  (patient as Patient).getAuditData = originalGetAuditData.bind(patient);

  return patient as Patient;
}

/**
 * Creates a copy of mock medical history with specified overrides
 * 
 * @param baseHistory - Base medical history to copy
 * @param overrides - Properties to override
 * @returns New medical history object with overrides applied
 */
export function createMockMedicalHistory(
  baseHistory: MedicalHistory = mockMedicalHistory1,
  overrides: Partial<MedicalHistory> = {}
): MedicalHistory {
  return {
    ...baseHistory,
    ...overrides,
  } as MedicalHistory;
}

/**
 * Creates a mock auth user from a patient
 * 
 * @param patient - Patient to convert
 * @returns Auth user object
 */
export function createMockAuthUser(patient: Patient = mockRegularPatient): MockAuthUser {
  return {
    id: patient.id,
    email: patient.email,
    firstName: patient.firstName,
    lastName: patient.lastName,
    role: patient.role as Role,
    passwordVersion: patient.passwordVersion || 1,
  };
}
