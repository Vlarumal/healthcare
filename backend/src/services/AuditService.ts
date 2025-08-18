import { AuditLog, AuditAction } from '../entities/AuditLog';
import { Patient } from '../entities/Patient';
import { AppDataSource } from '../data-source';
import { Request } from 'express';

export class AuditService {
  private auditLogRepository = AppDataSource.getRepository(AuditLog);

  async logPatientAction(
    action: AuditAction,
    patient: Patient,
    performedById: number,
    details: Record<string, any>
  ) {
    const auditLog = new AuditLog();
    auditLog.action = action;
    auditLog.patient = patient;
    auditLog.performedById = performedById;
    auditLog.details = details;

    await this.auditLogRepository.save(auditLog);
  }

  async logError(error: Error, request: Request) {
    const auditLog = new AuditLog();
    auditLog.action = AuditAction.SYSTEM_ERROR;
    auditLog.details = {
      error: error.message,
      stack: error.stack,
      path: request.path,
      method: request.method
    };

    await this.auditLogRepository.save(auditLog);
  }
}