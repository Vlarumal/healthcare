  import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { Patient } from './Patient';
import { IsDate, IsOptional, IsString, Length } from 'class-validator';

@Entity()
export class MedicalHistory {
  @PrimaryGeneratedColumn()
  id!: number;

  @IsDate()
  @Column({ type: 'date' })
  date!: Date;

  @IsString()
  @Length(5, 500)
  @Column('text')
  diagnosis!: string;

  @IsString()
  @Length(5, 500)
  @Column('text')
  treatment!: string;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  @Column({ type: 'text', nullable: true })
  notes?: string | null;

  @IsOptional()
  @Length(1, 200)
  @Column({ nullable: true })
  allergies?: string;

  // @ManyToOne('Patient', (patient: Patient) => patient.medicalHistories)
  // patient!: Patient;
  @ManyToOne(() => Patient, { onDelete: 'CASCADE' })
  patient!: Patient;


  toJSON() {
    return {
      ...this,
      date: this.date ? new Date(this.date).toISOString().split('T')[0] : null,
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString()
    };
  }
}