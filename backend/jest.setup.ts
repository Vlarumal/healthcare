import 'reflect-metadata';
import 'dotenv/config';
import { AppDataSource } from './src/data-source';
jest.mock('./src/utils/mailer', () => ({
  transporter: {
    sendMail: jest.fn().mockImplementation(() => Promise.resolve({ messageId: 'mocked-message-id' }))
  }
}));

jest.mock('./src/utils/tempPasswordUtils', () => ({
  setTemporaryPassword: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('./src/data-source', () => {
  class MockQueryRunner {
    connect = jest.fn().mockResolvedValue(undefined);
    startTransaction = jest.fn().mockResolvedValue(undefined);
    commitTransaction = jest.fn().mockResolvedValue(undefined);
    rollbackTransaction = jest.fn().mockResolvedValue(undefined);
    release = jest.fn().mockResolvedValue(undefined);
    manager = {
      connection: {},
      queryRunner: this
    };
  }

  const mockAppDataSource = {
    initialize: jest.fn().mockResolvedValue(undefined),
    destroy: jest.fn().mockResolvedValue(undefined),
    isInitialized: false,
    createQueryRunner: jest.fn(() => new MockQueryRunner()),
    getRepository: jest.fn(),
  };

  return {
    AppDataSource: mockAppDataSource
  };
});

beforeAll(async () => {
  await AppDataSource.initialize();
});

beforeEach(async () => {
  const queryRunner = AppDataSource.createQueryRunner();
  await queryRunner.connect();
  await queryRunner.startTransaction();
  (global as any).testQueryRunner = queryRunner;
});

afterEach(async () => {
  const queryRunner = (global as any).testQueryRunner;
  if (queryRunner) {
    await queryRunner.rollbackTransaction();
    await queryRunner.release();
    delete (global as any).testQueryRunner;
  }
});

afterAll(async () => {
});
