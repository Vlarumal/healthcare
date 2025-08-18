import { AppDataSource } from './src/data-source';

async function checkSchema() {
  try {
    await AppDataSource.initialize();
    console.log('Database connection established');
    
    const result = await AppDataSource.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'patient'
      ORDER BY ordinal_position
    `);
    
    console.log('Patient table columns:');
    console.table(result);
    
    await AppDataSource.destroy();
    process.exit(0);
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

checkSchema();