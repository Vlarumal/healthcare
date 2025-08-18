export const DEFAULT_REQUIREMENTS = [
  {
    text: 'At least 8 characters',
    validator: (p: string) => p.length >= 8
  },
  {
    text: 'At least one lowercase letter',
    validator: (p: string) => /[a-z]/.test(p)
  },
  {
    text: 'At least one uppercase letter',
    validator: (p: string) => /[A-Z]/.test(p)
  },
  {
    text: 'At least one number',
    validator: (p: string) => /[0-9]/.test(p)
  },
  {
    text: 'At least one special character (!@#$%^&*(),.?":{}|<>)',
    validator: (p: string) => /[!@#$%^&*(),.?":{}|<>]/.test(p)
  }
];

export const validatePassword = (password: string): string[] => {
  return DEFAULT_REQUIREMENTS
    .filter(req => !req.validator(password))
    .map(req => req.text);
};