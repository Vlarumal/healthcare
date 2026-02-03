#!/usr/bin/env node
import { AppDataSource } from '../src/data-source';
import { Patient, Gender, Role } from '../src/entities/Patient';
import { MedicalHistory } from '../src/entities/MedicalHistory';
import { AuditLog } from '../src/entities/AuditLog';
import { Token } from '../src/entities/Token';
import { faker } from '@faker-js/faker/locale/en_US';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import path from 'path';

// Load .env from the project root (works for both src/ and build/ directories)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const MEDICAL_CONDITIONS = [
  'Hypertension', 'Type 2 Diabetes', 'Asthma', 'Osteoarthritis', 
  'Migraine', 'Hyperlipidemia', 'GERD', 'Generalized Anxiety Disorder'
];

const TREATMENTS = [
  'Lisinopril 10mg daily', 'Metformin 500mg twice daily', 
  'Albuterol inhaler as needed', 'Atorvastatin 20mg at bedtime',
  'Omeprazole 20mg daily', 'Sertraline 50mg daily',
  'Levothyroxine 75mcg daily', 'Amlodipine 5mg daily'
];

const DEFAULT_PASSWORD = 'Password123!'; // For development only

async function seedDatabase() {
  await AppDataSource.initialize();
  const patientRepo = AppDataSource.getRepository(Patient);
  const historyRepo = AppDataSource.getRepository(MedicalHistory);
  const auditLogRepo = AppDataSource.getRepository(AuditLog);
  const tokenRepo = AppDataSource.getRepository(Token);

  await historyRepo.createQueryBuilder().delete().execute();
  await auditLogRepo.createQueryBuilder().delete().execute();
  await tokenRepo.createQueryBuilder().delete().execute();
  await patientRepo.createQueryBuilder().delete().execute();
  console.log('Cleared existing data');

  const patients: Patient[] = [];
  for (let i = 0; i < 20; i++) {
    const patient = new Patient();
    patient.firstName = faker.person.firstName();
    patient.lastName = faker.person.lastName();
    patient.dateOfBirth = faker.date.birthdate({ min: 18, max: 90, mode: 'age' });
    patient.gender = faker.helpers.arrayElement([
      Gender.MALE, 
      Gender.FEMALE, 
      Gender.OTHER, 
      Gender.UNSPECIFIED
    ]);
   patient.email = faker.internet.email();
   const countryCodes = ['1', '44', '49', '33', '81', '82', '61', '52', '39', '34', '370'];
   const countryCode = faker.helpers.arrayElement(countryCodes);
   let numberLength: number;
   switch (countryCode) {
     case '1': // US/Canada
       numberLength = 10;
       break;
     case '44': // UK
       numberLength = 10;
       break;
     case '49': // Germany
     case '33': // France
       numberLength = 9;
       break;
     case '81': // Japan
     case '82': // South Korea
     case '61': // Australia
     case '39': // Italy
     case '34': // Spain
      numberLength = 9;
      break;
    case '370': // Lithuania
      numberLength = 8;
      break;
    case '52': // Mexico
      numberLength = 8;
      break;
     default:
       numberLength = 9;
   }
   patient.phoneNumber = '+' + countryCode + faker.string.numeric(numberLength);
   patient.password = await bcrypt.hash(DEFAULT_PASSWORD, 10);
    patient.role = Role.PATIENT;
    patient.address = faker.location.streetAddress();
    patient.city = faker.location.city();
    patient.zipCode = faker.location.zipCode();
    
    patients.push(await patientRepo.save(patient));
  }

  for (const patient of patients) {
    const history = new MedicalHistory();
    history.patient = patient;
    history.date = faker.date.past({ years: 5 });
    history.diagnosis = faker.helpers.arrayElement(MEDICAL_CONDITIONS);
    history.treatment = faker.helpers.arrayElement(TREATMENTS);
    history.notes = faker.lorem.sentences(2);
    history.allergies = faker.helpers.arrayElement([
      'Penicillin', 'Latex', 'Pollen', 'Dust mites', 'Shellfish', 'None'
    ]);
    
    await historyRepo.save(history);
  }

  console.log(`Created ${patients.length} patients with medical histories`);
  console.log(`All patients use password: ${DEFAULT_PASSWORD}`);
  await AppDataSource.destroy();
}

seedDatabase().catch(error => {
  console.error('Seeding failed:', error);
  process.exit(1);
});