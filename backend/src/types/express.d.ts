import { Request } from 'express';
import { z } from 'zod';

declare module 'express-serve-static-core' {
  interface Request {
    validatedData?: any;
    user?: {
      id: number;
      role: 'patient' | 'staff' | 'admin' | 'clinician';
      tokenVersion: number;
    };
  }
}

export interface AuthenticatedRequest extends Request {
  user: {
    id: number;
    role: 'patient' | 'staff' | 'admin' | 'clinician';
    tokenVersion: number;
  };
}
