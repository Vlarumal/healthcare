import { Request, Response, NextFunction } from 'express';
import {
  Consent,
  ConsentStatus,
  ConsentType,
} from '../entities/Consent';
import { MoreThan } from 'typeorm';
import { AppDataSource } from '../index';

export const checkConsent = (consentType: string) => {
  return async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const consentRepo = AppDataSource.getRepository(Consent);

      const validConsent = await consentRepo.findOne({
        where: {
          type: consentType as ConsentType,
          status: ConsentStatus.GRANTED,
          expiration: MoreThan(new Date()),
        },
      });

      if (!validConsent) {
        res.status(403).json({
          error: `Consent required for ${consentType} operation`,
        });
        return;
      }

      next();
    } catch (error) {
      console.error('Consent verification error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  };
};
