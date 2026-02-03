#!/usr/bin/env node
import { AppDataSource } from '../src/data-source';
import dotenv from 'dotenv';
import path from 'path';
import { DataSource } from 'typeorm';

// Load .env from the project root (works for both src/ and build/ directories)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

async function dropDatabase() {
  const { host, port, username, password } = AppDataSource.options as any;
  
  const adminDataSource = new DataSource({
    type: 'postgres',
    host,
    port,
    username,
    password,
    database: 'postgres' // Connect to default DB
  });

  try {
    await adminDataSource.initialize();
    
    const dbName = process.env.DB_NAME;
    
    const dbExists = await adminDataSource.query(
      `SELECT 1 FROM pg_database WHERE datname = $1`,
      [dbName]
    );

    if (dbExists.length > 0) {
      await adminDataSource.query(`
        SELECT pg_terminate_backend(pg_stat_activity.pid)
        FROM pg_stat_activity
        WHERE pg_stat_activity.datname = $1
          AND pid <> pg_backend_pid();
      `, [dbName]);

      await adminDataSource.query(`DROP DATABASE "${dbName}"`);
      console.log(`Database ${dbName} dropped successfully`);
    } else {
      console.log(`Database ${dbName} does not exist`);
    }

    await adminDataSource.destroy();
  } catch (error) {
    console.error('Database drop failed:', error instanceof Error ? error.message : error);
    if (error instanceof Error && error.stack) {
      console.debug('Stack trace:', error.stack);
    }
    process.exit(1);
  }
}

dropDatabase();