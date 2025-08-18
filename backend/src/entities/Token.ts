import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn } from 'typeorm';
import { Patient } from './Patient';

@Entity()
export class Token {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column()
  token!: string;

  @Column()
  type!: 'refresh' | 'access';

  @Column()
  expiresAt!: Date;

  @Column({ default: false })
  revoked: boolean = false;

  @ManyToOne(() => Patient, patient => patient.tokens)
  @JoinColumn({ name: 'patient_id' })
  patient!: Patient;
}