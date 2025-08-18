import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne } from 'typeorm';
import { IsEnum, IsNumber } from 'class-validator';
import { Patient } from './Patient';

export enum AuditAction {
  CREATE_PATIENT = 'CREATE_PATIENT',
  UPDATE_PATIENT = 'UPDATE_PATIENT',
  DELETE_PATIENT = 'DELETE_PATIENT',
  VIEW_PATIENT = 'VIEW_PATIENT',
  VIEW_OWN_PATIENT = 'VIEW_OWN_PATIENT',
  SYSTEM_ERROR = 'SYSTEM_ERROR'
}

@Entity()
export class AuditLog {
  @PrimaryGeneratedColumn()
  id!: number;

  @IsEnum(AuditAction)
  @Column({ type: 'enum', enum: AuditAction })
  action!: AuditAction;

  @ManyToOne(() => Patient, (patient) => patient.auditLogs)
  patient!: Patient;

  @IsNumber()
  @Column()
  performedById!: number;

  @Column('jsonb')
  details!: Record<string, unknown>;

  @CreateDateColumn()
  timestamp!: Date;

  constructor(data?: Partial<AuditLog>) {
    Object.assign(this, data);
  }
}