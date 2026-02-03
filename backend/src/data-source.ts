import { DataSource } from 'typeorm';
import { Patient } from './entities/Patient';
import { MedicalHistory } from './entities/MedicalHistory';
import { Consent } from './entities/Consent';
import { AuditLog } from './entities/AuditLog';
import dotenv from 'dotenv';
import path from 'path';
import { Token } from './entities/Token';

// Load .env from the project root (works for both src/ and build/ directories)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.NODE_ENV === 'test' ? process.env.DB_TEST_USER : process.env.DB_USER,
  password: process.env.NODE_ENV === 'test' ? process.env.DB_TEST_PASSWORD : process.env.DB_PASSWORD,
  database: process.env.NODE_ENV === 'test' ? process.env.DB_TEST_NAME : process.env.DB_NAME,
  synchronize: true,
  logging: false,
  // cache: {
  //   type: 'database',
  //   duration: 300000, // 5 minutes cache
  //   alwaysEnabled: true,
  // },
  entities: [
    Patient,
    MedicalHistory,
    Consent,
    AuditLog,
    Token,
  ],
  migrations: [],
  subscribers: [],
});