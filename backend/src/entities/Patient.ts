import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToMany,
  DeleteDateColumn,
  Index,
  CreateDateColumn,
} from 'typeorm';
import { MedicalHistory } from './MedicalHistory';
import { Consent } from './Consent';
import { AuditLog } from './AuditLog';
import {
  IsDate,
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  Length,
  Matches,
  MaxDate,
  IsInt,
  Min
} from 'class-validator';
import { Token } from './Token';

export enum Gender {
  MALE = 'male',
  FEMALE = 'female',
  OTHER = 'other',
  UNSPECIFIED = 'unspecified'
}

export enum Role {
  PATIENT = 'patient',
  STAFF = 'staff',
  ADMIN = 'admin',
  CLINICIAN = 'clinician',
  GUEST = 'guest'
}

@Entity()
export class Patient {
  @PrimaryGeneratedColumn()
  id!: number;

  @DeleteDateColumn({ name: 'deleted_at', nullable: true })
  @Index()
  deletedAt?: Date;

  @CreateDateColumn({ name: 'created_at' })
  @Index()
  createdAt!: Date;


  @IsString()
  @Length(1, 50)
  @Column()
  firstName!: string;

  @IsString()
  @Length(1, 50)
  @Column()
  lastName!: string;

  @IsEmail()
  @Column({ unique: true })
  email!: string;

  @IsString()
  @Column()
  password!: string;

  @IsDate()
  @MaxDate(new Date(), { message: 'Birth date must be in the past' })
  @Column({ type: 'date' })
  dateOfBirth!: Date;

  @IsOptional()
  @IsEnum(Gender)
  @Column({ type: 'enum', enum: Gender, nullable: true })
  gender?: Gender;

  @IsOptional()
  @Matches(/^\+?[1-9]\d{1,14}$/, { message: 'Phone must be in E.164 format' })
  @Column({ nullable: true })
  @Column({ type: 'varchar', nullable: true })
  phoneNumber?: string | null;

  @IsOptional()
  @Length(1, 100)
  @Column({ type: 'text', nullable: true })
  address?: string | null;

  @IsOptional()
  @Length(1, 50)
  @Column({ type: 'text', nullable: true })
  city?: string | null;

  @IsOptional()
  // @Length(5, 10)
  @Column({ type: "text", nullable: true })
  zipCode?: string | null;

  @IsEnum(Role)
  @Column({
    type: 'enum',
    enum: Role,
    default: Role.PATIENT
  })
  role!: Role;

  @IsInt()
  @Min(1)
  @Column({ default: 1 })
  passwordVersion!: number;

  @Column({ type: 'varchar', nullable: true })
  temporaryPassword?: string | null;

  @Column({ type: 'boolean', default: false })
  resetRequired!: boolean;

  @OneToMany(() => MedicalHistory, (history) => history.patient, {
    cascade: true,
  })
  medicalHistories?: MedicalHistory[];

  @OneToMany(() => Consent, (consent) => consent.patient, {
    cascade: true,
  })
  consents!: Consent[];

  @OneToMany(() => AuditLog, (log) => log.patient)
  auditLogs!: AuditLog[];

  @OneToMany(() => Token, token => token.patient)
  tokens!: Token[];

  toJSON() {
    const { password, temporaryPassword, passwordVersion, tokens, ...rest } = this;
    return {
      ...rest,
      dateOfBirth: this.dateOfBirth instanceof Date
        ? this.dateOfBirth.toISOString().split('T')[0]
        : this.dateOfBirth
    };
  }

  getAuditData(): object {
    return {
      firstName: this.firstName,
      lastName: this.lastName,
      email: this.email,
      role: this.role
    };
  }
}


