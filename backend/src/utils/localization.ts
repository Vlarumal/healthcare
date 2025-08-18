import { Request } from 'express';
import { LocalizedError } from '../errors/LocalizedError';

export type Language = 'en' | 'uk' | 'lt' | 'ru';
type ErrorKeys = 'ConsentNotFoundError' | 'ConsentExpiredError' | 'InvalidConsentStatusError' | 'PatientNotFoundError' | 'UserNotFoundError' | 'TokenRotationError' | 'DatabaseConnectionError' | 'DatabaseQueryError' | 'RecordNotFoundError';
type Translations = Record<ErrorKeys, Record<Language, string>>;

const translations: Translations = {
  ConsentNotFoundError: {
    en: 'Consent with id {0} not found',
    uk: 'Згоду з id {0} не знайдено',
    lt: 'Sutikimas su ID {0} nerastas',
    ru: 'Согласие с ID {0} не найдено'
  },
  ConsentExpiredError: {
    en: 'Consent with id {0} has expired',
    uk: 'Згода з id {0} закінчилася',
    lt: 'Sutikimas su ID {0} pasibaigė',
    ru: 'Согласие с ID {0} истекло'
  },
  InvalidConsentStatusError: {
    en: 'Consent with id {0} has invalid status: {1}',
    uk: 'Згода з id {0} має недійсний статус: {1}',
    lt: 'Sutikimas su ID {0} turi neteisingą būseną: {1}',
    ru: 'Согласие с ID {0} имеет недопустимый статус: {1}'
  },
  PatientNotFoundError: {
    en: 'Patient not found',
    uk: 'Пацієнта не знайдено',
    lt: 'Pacientas nerastas',
    ru: 'Пациент не найден'
  },
  UserNotFoundError: {
    en: 'User not found',
    uk: 'Користувача не знайдено',
    lt: 'Vartotojas nerastas',
    ru: 'Пользователь не найден'
  },
  TokenRotationError: {
    en: 'Token rotation failed',
    uk: 'Помилка обертання токена',
    lt: 'Nepavyko apversti žetono',
    ru: 'Ошибка смены токена'
  },
  DatabaseConnectionError: {
    en: 'Database connection failed',
    uk: 'Помилка підключення до бази даних',
    lt: 'Duomenų bazės ryšio klaida',
    ru: 'Ошибка подключения к базе данных'
  },
  DatabaseQueryError: {
    en: 'Database query failed',
    uk: 'Помилка запиту до бази даних',
    lt: 'Duomenų bazės užklausos klaida',
    ru: 'Ошибка запроса к базе данных'
  },
  RecordNotFoundError: {
    en: '{0} with identifier {1} not found',
    uk: 'Пацієнта з ідентифікатором {1} не знайдено',
    lt: 'Įrašas „Patient“ su identifikatoriumi {1} nerastas',
    ru: 'Запись Patient с идентификатором {1} не найдена'
  }
};

export function localizeError(error: LocalizedError, lang: Language = 'en'): string {
  const template = translations[error.name as ErrorKeys]?.[lang] || error.message;
  
  if (!error.args || !Array.isArray(error.args)) {
    return template;
  }

  const args = error.args;
  
  // Special handling for RecordNotFoundError to translate record types in non-English languages
  if (error.name === 'RecordNotFoundError' && args.length >= 2) {
    const recordType = args[0];
    const identifier = args[1];
    
    // For English, use the template as is with placeholders
    if (lang === 'en') {
      return template.replace('{0}', recordType?.toString() || '{0}')
                    .replace('{1}', identifier?.toString() || '{1}');
    }
    
    // For other languages, translate common record types
    const translatedRecordType = getLocalizedRecordType(recordType?.toString() || '', lang);
    return template.replace('{1}', identifier?.toString() || '{1}')
                  .replace('{0}', translatedRecordType);
  }
  
  // Replace placeholders with arguments for other errors
  // More efficient string replacement without regex
  let result = template;
  for (let i = 0; i < args.length; i++) {
    result = result.replace(`{${i}}`, args[i]?.toString() || `{${i}}`);
  }
  return result;
}

const recordTypeTranslations: Record<string, Record<Language, string>> = {
  'Patient': {
    en: 'Patient',
    uk: 'Пацієнта',
    lt: 'Įrašas „Patient“',
    ru: 'Запись Patient'
  }
};

function getLocalizedRecordType(recordType: string, lang: Language): string {
  return recordTypeTranslations[recordType]?.[lang] || recordType;
}

export function getRequestLanguage(req: Request): Language {
  const acceptLanguage = req.headers['accept-language'];
  if (!acceptLanguage) {
    return 'en';
  }

  const languages = acceptLanguage.split(',');
  
  for (const langEntry of languages) {
    const lang = langEntry.trim().split('-')[0].toLowerCase();
    
    if (lang === 'uk' || lang === 'lt' || lang === 'ru') {
      return lang as Language;
    }
  }

  return 'en';
}

export function getLanguageFromRequest(req: Request): Language {
  return getRequestLanguage(req);
}