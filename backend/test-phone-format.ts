import { AppDataSource } from './src/data-source';
import { Patient } from './src/entities/Patient';

async function validateE164Format() {
  await AppDataSource.initialize();
  const patients = await AppDataSource.getRepository(Patient).find({ take: 10 });
  console.log('E.164 Format Validation:');
  patients.forEach(patient => {
    if (patient.phoneNumber && typeof patient.phoneNumber === 'string') {
      const isValid = /^\+[1-9]\d{1,14}$/.test(patient.phoneNumber);
      console.log(`Phone: ${patient.phoneNumber} - Valid: ${isValid}`);
    } else {
      console.log(`Phone: ${patient.phoneNumber} - Valid: false (null or undefined)`);
    }
  });
  await AppDataSource.destroy();
}

validateE164Format().catch(console.error);