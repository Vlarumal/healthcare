import { Gender, Patient, Role } from '../entities/Patient';
import { Repository } from 'typeorm';
import { AuditService } from './AuditService';
import { PasswordService } from './passwordService';
import { EmailService } from './emailService';
import { AuditAction } from '../entities/AuditLog';
import { PatientNotFoundError } from '../errors/patientErrors';
import { BadRequestError, InternalServerError } from '../errors/httpErrors';
import logger from '../utils/logger';

type PublicPatient = Omit<Patient, 'password' | 'toJSON' | 'getAuditData'>;

interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
  };
}

interface PatientCreateData {
  firstName: string;
  lastName: string;
  email: string;
  dateOfBirth: Date;
  gender: Gender;
  phoneNumber?: string | null;
}

interface PatientUpdateData {
  firstName?: string;
  lastName?: string;
  email?: string;
  dateOfBirth?: Date;
  gender?: Gender;
  phoneNumber?: string | null;
  address?: string | null;
  city?: string | null;
  zipCode?: string | null;
  role?: Role;
}

interface PatientFilters {
  id?: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  gender?: Gender;
  startDate?: string;
  endDate?: string;
  role?: string;
}

interface PatientServiceDependencies {
  patientRepository: Repository<Patient>;
  auditService: AuditService;
  passwordService: PasswordService;
  emailService: EmailService;
}

export const PatientService = (deps: PatientServiceDependencies) => {
  const {
    patientRepository,
    auditService,
    passwordService,
    emailService,
  } = deps;

  return {
    async getAllowedRoles(): Promise<string[]> {
      try {
        const roles = await patientRepository
          .createQueryBuilder('patient')
          .select('DISTINCT(patient.role)', 'role')
          .getRawMany();
        
        return roles.map(r => r.role);
      } catch (error) {
        logger.error('Error getting allowed roles:', error);
        throw new InternalServerError('Failed to retrieve roles');
      }
    },

    async getPatients(
      page: number = 1,
      pageSize: number = 10,
      filters: PatientFilters = {},
      sort: { field: string; direction: 'ASC' | 'DESC'; caseInsensitive?: boolean } = {
        field: 'lastName',
        direction: 'ASC',
      }
    ): Promise<PaginatedResponse<PublicPatient>> {
      try {
        page = Math.max(1, page);
        pageSize = Math.max(1, Math.min(100, pageSize));
        
        const allowedSortFields = ['firstName', 'lastName', 'email', 'dateOfBirth', 'gender', 'phoneNumber', 'id'];
        if (!allowedSortFields.includes(sort.field)) {
          throw new BadRequestError(`Invalid sort field: ${sort.field}. Allowed fields: ${allowedSortFields.join(', ')}`);
        }
        
        if (filters.role) {
          const allowedRoles = await this.getAllowedRoles();
          if (!allowedRoles.includes(filters.role)) {
            throw new BadRequestError(`Invalid role: ${filters.role}. Allowed roles: ${allowedRoles.join(', ')}`);
          }
        }
        
        const queryBuilder = patientRepository.createQueryBuilder('patient');
        
        if (filters.id) {
          queryBuilder.andWhere('patient.id = :id', { id: filters.id });
        }
        if (filters.firstName) {
          queryBuilder.andWhere('patient.firstName ILike :firstName', { firstName: `%${filters.firstName}%` });
        }
        if (filters.lastName) {
          queryBuilder.andWhere('patient.lastName ILike :lastName', { lastName: `%${filters.lastName}%` });
        }
        if (filters.email) {
          queryBuilder.andWhere('patient.email ILike :email', { email: `%${filters.email}%` });
        }
        if (filters.gender) {
          queryBuilder.andWhere('patient.gender = :gender', { gender: filters.gender });
        }
        if (filters.role) {
          queryBuilder.andWhere('patient.role = :role', { role: filters.role });
        }
        if (filters.startDate || filters.endDate) {
          const startDate = filters.startDate ? new Date(filters.startDate) : null;
          const endDate = filters.endDate ? new Date(filters.endDate) : null;
          
          if (filters.startDate && (!startDate || isNaN(startDate.getTime()))) {
            throw new BadRequestError('Invalid startDate format');
          }
          if (filters.endDate && (!endDate || isNaN(endDate.getTime()))) {
            throw new BadRequestError('Invalid endDate format');
          }
          
          if (startDate && endDate) {
            queryBuilder.andWhere('patient.dateOfBirth BETWEEN :startDate AND :endDate', { startDate, endDate });
          } else if (startDate) {
            queryBuilder.andWhere('patient.dateOfBirth >= :startDate', { startDate });
          } else if (endDate) {
            queryBuilder.andWhere('patient.dateOfBirth <= :endDate', { endDate });
          }
        }
        
        const stringFields = ['firstName', 'lastName', 'email'];
        if (sort.caseInsensitive && stringFields.includes(sort.field)) {
          queryBuilder.orderBy(`LOWER(patient.${sort.field})`, sort.direction);
        } else {
          queryBuilder.orderBy(`patient.${sort.field}`, sort.direction);
        }
      
        const skip = (page - 1) * pageSize;
        const take = pageSize;
        queryBuilder.offset(skip);
        queryBuilder.limit(take);
        
        const [patients, total] = await queryBuilder.getManyAndCount();
        
        const publicPatients = patients.map(patient => {
          const { password, ...publicData } = patient;
          return publicData as PublicPatient;
        });
        
        return {
          data: publicPatients,
          pagination: {
            total,
            page,
            pageSize,
            totalPages: Math.ceil(total / pageSize),
          },
        };
      } catch (error) {
        if (error instanceof BadRequestError) {
          throw error;
        }
        logger.error('Error in getPatients:', error);
        throw new InternalServerError('Failed to retrieve patients');
      }
    },

    async getPatientById(id: number | 'me', viewer: { id: number }): Promise<Patient | null> {
      try {
        if (id === 'me') {
          const patient = await patientRepository.findOne({
            where: { id: viewer.id },
            relations: ['medicalHistories']
          });
          if (!patient) return null;
          return patient;
        }
        
        const patient = await patientRepository.findOne({
          where: { id },
          relations: ['medicalHistories']
        });
        if (!patient) return null;

        if (patient.id !== viewer.id) {
          await auditService.logPatientAction(
            AuditAction.VIEW_PATIENT,
            patient,
            viewer.id,
            { viewedFields: ['id', 'medicalHistory'] }
          );
        }

        return patient;
      } catch (error) {
        logger.error('Error in getPatientById:', error);
        throw new InternalServerError('Failed to retrieve patient');
      }
    },

    async createPatient(
      data: PatientCreateData,
      createdBy: { id: number }
    ): Promise<Patient> {
      try {
        const tempPassword =
          passwordService.generateTemporaryPassword();
        const hashedTempPassword = await passwordService.hashPassword(
          tempPassword
        );

        const patient = new Patient();
        Object.assign(patient, data);
        patient.password = hashedTempPassword;
        patient.resetRequired = true;

        const savedPatient = await patientRepository.save(patient);
        await emailService.sendTemporaryPasswordEmail(
          data.email,
          tempPassword
        );

        await auditService.logPatientAction(
          AuditAction.CREATE_PATIENT,
          savedPatient,
          createdBy.id,
          {
            firstName: savedPatient.firstName,
            lastName: savedPatient.lastName,
          }
        );

        return savedPatient;
      } catch (error) {
        logger.error('Error in createPatient:', error);
        throw new InternalServerError('Failed to create patient');
      }
    },

    async updatePatient(
      id: number,
      data: PatientUpdateData,
      updatedBy: { id: number }
    ): Promise<Patient> {
      try {
        const patient = await patientRepository.findOne({ where: { id } });
        if (!patient) throw new PatientNotFoundError();

        const originalValues: any = {
          firstName: patient.firstName,
          lastName: patient.lastName,
          email: patient.email,
          dateOfBirth: patient.dateOfBirth,
        };

        if (data.role !== undefined) {
          originalValues.role = patient.role;
        }
        
        if (data.address !== undefined) {
          originalValues.address = patient.address;
        }
        if (data.city !== undefined) {
          originalValues.city = patient.city;
        }
        if (data.zipCode !== undefined) {
          if (!patient.id) {
            throw new BadRequestError('Invalid patient record');
          }
          originalValues.zipCode = patient.zipCode;
        }

        Object.assign(patient, data);
        const updatedPatient = await patientRepository.save(patient);

        const updatedValues: any = {
          firstName: updatedPatient.firstName,
          lastName: updatedPatient.lastName,
          email: updatedPatient.email,
          dateOfBirth: updatedPatient.dateOfBirth,
        };

        if (data.role !== undefined) {
          updatedValues.role = updatedPatient.role;
        }
        
        if (data.address !== undefined) {
          updatedValues.address = updatedPatient.address;
        }
        if (data.city !== undefined) {
          updatedValues.city = updatedPatient.city;
        }
        if (data.zipCode !== undefined) {
          updatedValues.zipCode = updatedPatient.zipCode;
        }

        await auditService.logPatientAction(
          AuditAction.UPDATE_PATIENT,
          patient,
          updatedBy.id,
          {
            original: originalValues,
            updated: updatedValues,
          }
        );

        return updatedPatient;
      } catch (error) {
        if (error instanceof PatientNotFoundError) {
          throw error;
        }
        logger.error('Error in updatePatient:', error);
        throw new InternalServerError('Failed to update patient');
      }
    },

    async deletePatient(id: number, deletedBy: { id: number }): Promise<void> {
      try {
        const patient = await patientRepository.findOne({ where: { id } });
        if (!patient) throw new PatientNotFoundError();

        const patientData = patient.getAuditData();

        await patientRepository.softDelete(id);

        await auditService.logPatientAction(
          AuditAction.DELETE_PATIENT,
          patient,
          deletedBy.id,
          patientData
        );
      } catch (error) {
        if (error instanceof PatientNotFoundError) {
          throw error;
        }
        logger.error('Error in deletePatient:', error);
        throw new InternalServerError('Failed to delete patient');
      }
    },
  };
};
