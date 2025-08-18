export interface SignupCredentials {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  dateOfBirth: string;
}

export interface User {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  dateOfBirth: string;
  gender?: 'male' | 'female' | 'other' | 'unspecified';
  phoneNumber?: string;
  address?: string;
  city?: string;
  zipCode?: string;
  role: 'patient' | 'staff' | 'admin' | 'clinician';
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}
