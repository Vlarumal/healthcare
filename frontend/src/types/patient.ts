export interface Patient {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  dateOfBirth: string;
  gender?: 'male' | 'female' | 'other' | 'unspecified';
  phoneNumber?: string | null;
  address?: string;
  city?: string;
  zipCode?: string | null;
  role: 'patient' | 'staff' | 'admin' | 'clinician';
}

export type PatientFormData = {
  id?: string;
  firstName: string;
  lastName: string;
  email: string;
  dateOfBirth: string;
  gender?: 'male' | 'female' | 'other' | 'unspecified';
  phoneNumber?: string | null;
  address?: string;
  city?: string;
  zipCode?: string | null;
  role?: 'patient' | 'staff' | 'admin' | 'clinician';
};
