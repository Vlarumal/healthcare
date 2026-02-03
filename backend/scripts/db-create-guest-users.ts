#!/usr/bin/env node
import { AppDataSource } from '../src/data-source';
import { Patient, Role, Gender } from '../src/entities/Patient';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import path from 'path';

// Load .env from the project root (works for both src/ and build/ directories)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

// TEMPORARY DEMO PASSWORD - CHANGE BEFORE PRODUCTION!
const GUEST_PASSWORD = process.env.GUEST_PASSWORD!;

async function createGuestUsers() {
  await AppDataSource.initialize();
  const patientRepo = AppDataSource.getRepository(Patient);
  
  const guestUsers = [
    {
      email: 'guest@example.com',
      role: Role.GUEST,
      firstName: 'Guest',
      lastName: 'User'
    },
    {
      email: 'guest_patient@example.com',
      role: Role.PATIENT,
      firstName: 'Guest',
      lastName: 'Patient'
    },
    {
      email: 'guest_clinician@example.com',
      role: Role.CLINICIAN,
      firstName: 'Guest',
      lastName: 'Clinician'
    },
    {
      email: 'guest_staff@example.com',
      role: Role.STAFF,
      firstName: 'Guest',
      lastName: 'Staff'
    },
    {
      email: 'guest_admin@example.com',
      role: Role.ADMIN,
      firstName: 'Guest',
      lastName: 'Admin'
    }
  ];

  try {
    const existingEmails = guestUsers.map(g => g.email);
    const existingUsers = await patientRepo.find({
      where: existingEmails.map(email => ({ email }))
    });
    const existingEmailsSet = new Set(existingUsers.map(u => u.email));
    
    const newGuests: Patient[] = [];
    for (const guest of guestUsers) {
      if (existingEmailsSet.has(guest.email)) {
        console.log(`Skipping existing guest: ${guest.email}`);
        continue;
      }
      
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(guest.email)) {
        console.error(`Invalid email format: ${guest.email}`);
        continue;
      }

      const guestUser = patientRepo.create({
        ...guest,
        password: await bcrypt.hash(GUEST_PASSWORD, 10),
        dateOfBirth: new Date(1985, 0, 1),
        gender: Gender.UNSPECIFIED,
        phoneNumber: '+15551234567',
        address: '123 Guest Street',
        city: 'Guestville',
        zipCode: '12345'
      });
      newGuests.push(guestUser);
    }
    
    if (newGuests.length > 0) {
      await patientRepo.save(newGuests);
      for (const guest of newGuests) {
        console.log(`Created guest user ${guest.email} with role ${guest.role}`);
      }
      console.log(`Guest user creation completed. ${newGuests.length} accounts created.`);
    } else {
      console.log('No new guest accounts created.');
    }
    console.log('==================================================');
    console.log('WARNING: USING TEMPORARY PASSWORD FOR ALL GUESTS');
    console.log(`Password: ${GUEST_PASSWORD}`);
    console.log('THIS IS INSECURE - CHANGE BEFORE PRODUCTION DEPLOYMENT!');
    console.log('==================================================');
    console.log('NOTICE: This is a temporary implementation for demonstration only');
    console.log('        Use secure password generation in production environments');
    console.log('==================================================');
  } catch (error) {
    console.error('Guest user creation failed:');
    if (error instanceof Error) {
      console.error(`Error name: ${error.name}`);
      console.error(`Error message: ${error.message}`);
      if (error.stack) console.error(`Stack trace: ${error.stack}`);
    } else {
      console.error(error);
    }
    process.exit(1);
  } finally {
    await AppDataSource.destroy();
  }
}

createGuestUsers();