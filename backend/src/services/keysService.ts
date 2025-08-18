import fs from 'fs';
import path from 'path';
import { InternalServerError } from '../errors/httpErrors';
import logger from '../utils/logger';

const JWKS_PATH = path.join(__dirname, '../../keys/jwks.json');

export const getPublicJWK = () => {
  try {
    const publicKey = fs.readFileSync(
      path.join(__dirname, '../../keys/public.pem'),
      'utf8'
    );
    
    return {
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      kid: '1',
      n: Buffer.from(
        publicKey
          .split('\n')
          .slice(1, -2)
          .join(''),
        'base64'
      ).toString('base64url'),
      e: 'AQAB'
    };
  } catch (error) {
    logger.error('Failed to read public key:', error);
    throw new InternalServerError('Failed to load public key');
  }
};

export const generateJWKS = () => {
  try {
    const jwks = {
      keys: [getPublicJWK()]
    };
    
    fs.writeFileSync(JWKS_PATH, JSON.stringify(jwks, null, 2));
    return jwks;
  } catch (error) {
    logger.error('Failed to generate JWKS:', error);
    throw new InternalServerError('Failed to generate JWKS');
  }
};

export const getJWKS = () => {
  try {
    return JSON.parse(fs.readFileSync(JWKS_PATH, 'utf8'));
  } catch (error) {
    return generateJWKS();
  }
};

export const getSigningKey = () => {
  try {
    return {
      kid: '1',
      alg: 'RS256',
      privateKey: fs.readFileSync(
        path.join(__dirname, '../../keys/private.pem'),
        'utf8'
      )
    };
  } catch (error) {
    logger.error('Failed to read private key:', error);
    throw new InternalServerError('Failed to load private key');
  }
};