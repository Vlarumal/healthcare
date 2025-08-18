#!/usr/bin/env node
import { AppDataSource } from '../src/data-source';
import dotenv from 'dotenv';
import { DataSource } from 'typeorm';

dotenv.config();

async function createDatabase() {
  const { host, port, username, password } = AppDataSource.options as any;
  
  const adminDataSource = new DataSource({
    type: 'postgres',
    host,
    port,
    username,
    password,
    database: 'postgres'
  });

  try {
    await adminDataSource.initialize();
    
    const result = await adminDataSource.query(
      `SELECT 1 FROM pg_database WHERE datname = $1`,
      [process.env.DB_NAME]
    );

    if (result.length === 0) {
      await adminDataSource.query(
        // `DROP DATABASE "${process.env.DB_NAME}"`
        //  OWNER "${process.env.DB_USER}"`
        `CREATE DATABASE "${process.env.DB_NAME}" 
         OWNER "${process.env.DB_USER}"`
      );
      console.log(`Database ${process.env.DB_NAME} created successfully`);
    } else {
      console.log(`Database ${process.env.DB_NAME} already exists`);
    }

    await adminDataSource.destroy();
  } catch (error) {
    console.error('Database creation failed:', error instanceof Error ? error.message : error);
    if (error instanceof Error && error.stack) {
      console.debug('Stack trace:', error.stack);
    }
    process.exit(1);
  }
}

createDatabase();