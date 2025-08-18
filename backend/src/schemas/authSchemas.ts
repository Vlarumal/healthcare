import { z } from 'zod';

export const signupSchema = z.object({
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Minimum 8 characters'),
  dateOfBirth: z.string().refine(val => !isNaN(Date.parse(val)), {
    message: 'Invalid date format'
  })
});

export const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required')
});

export const resetPasswordAuthenticatedSchema = z.object({
  newPassword: z.string().min(8, 'Minimum 8 characters')
});

export const resetPasswordUnauthenticatedSchema = z.object({
  email: z.string().email('Invalid email format'),
  newPassword: z.string().min(8, 'Minimum 8 characters')
});

export const requestTempPasswordSchema = z.object({
  email: z.string({ required_error: 'Email is required' }).email('Invalid email format')
});