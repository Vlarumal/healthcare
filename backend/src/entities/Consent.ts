import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import {
  IsDate,
  IsEnum,
  IsOptional,
} from 'class-validator';
import { Patient } from './Patient';

export enum ConsentType {
  TREATMENT = 'TREATMENT',
  SHARING = 'SHARING',
  RESEARCH = 'RESEARCH',
}

export enum ConsentStatus {
  GRANTED = 'GRANTED',
  REVOKED = 'REVOKED',
}

@Entity()
export class Consent {
  @PrimaryGeneratedColumn()
  id!: number;

  @IsEnum(ConsentType)
  @Column({ type: 'enum', enum: ConsentType })
  type!: ConsentType;

  @IsEnum(ConsentStatus)
  @Column({ type: 'enum', enum: ConsentStatus, default: ConsentStatus.GRANTED })
  status!: ConsentStatus;

  @IsOptional()
  @IsDate()
  @Column({ type: 'timestamp', nullable: true })
  expiration!: Date | null;

  @CreateDateColumn({ type: 'timestamp' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamp' })
  updatedAt!: Date;

  @ManyToOne(() => Patient, (patient) => patient.consents, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'patientId' })
  patient!: Patient;

  @Column()
  patientId!: number;
}