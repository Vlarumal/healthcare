export enum Role {
  PATIENT = 'patient',
  STAFF = 'staff',
  ADMIN = 'admin',
  CLINICIAN = 'clinician'
}

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        role: Role;
      };
    }
  }
}

export interface SignupDTO {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  dateOfBirth: string;
}

export interface LoginDTO {
  email: string;
  password: string;
}