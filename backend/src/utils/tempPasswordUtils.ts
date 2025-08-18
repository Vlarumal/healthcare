import { Patient } from '../entities/Patient';
import { AppDataSource } from '../data-source';
import { PasswordService } from '../services/passwordService';
import { EmailService } from '../services/emailService';
import { transporter } from './mailer';
import logger from './logger';

const passwordService = new PasswordService()
const emailService = new EmailService(transporter, logger);
export const setTemporaryPassword = async (email: string) => {
  const patientRepo = AppDataSource.getRepository(Patient);
  const patient = await patientRepo.findOneBy({ email });
  
  if (!patient) {
    throw new Error('Patient not found');
  }

  const tempPassword = passwordService.generateTemporaryPassword();
  const hashedTempPassword = await passwordService.hashPassword(tempPassword);

  patient.temporaryPassword = hashedTempPassword;
  patient.resetRequired = true;
  await patientRepo.save(patient);

  await emailService.sendTemporaryPasswordEmail(patient.email, tempPassword);
  
  return { success: true };
};