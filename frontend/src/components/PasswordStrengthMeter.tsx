import React, { useMemo, useState, useEffect } from 'react';
import {
  Box,
  LinearProgress,
  Typography,
  Collapse,
  useTheme
} from '@mui/material';
import { visuallyHidden } from '@mui/utils';
import CheckCircle from '@mui/icons-material/CheckCircle';
import Cancel from '@mui/icons-material/Cancel';
import LockOpen from '@mui/icons-material/LockOpen';
import Lock from '@mui/icons-material/Lock';
import Security from '@mui/icons-material/Security';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import { DEFAULT_REQUIREMENTS } from '../constants/passwordRequirements';

/**
 * Props for PasswordStrengthMeter component.
 *
 * @see {@link https://github.com/dropbox/zxcvbn} for password strength algorithm
 * @see {@link https://www.npmjs.com/package/zxcvbn} for npm package details
 */
interface PasswordStrengthMeterProps {
  password: string;
  minLength?: number;
  requirements?: Array<{
    text: string;
    validator: (password: string) => boolean;
  }>;
  onStrengthChange?: (strength: number) => void;
  onError?: (error: Error) => void;
  focusable?: boolean;
}

interface Requirement {
  text: string;
  valid: boolean;
  aria: string;
}

/**
 * PasswordRequirements component displays a list of password requirements and their status.
 */
const PasswordRequirements: React.FC<{
  password: string;
  requirements?: PasswordStrengthMeterProps['requirements'];
}> = ({ password, requirements = DEFAULT_REQUIREMENTS }) => {
  const theme = useTheme();
  
  const reqs: Requirement[] = useMemo(() => {
    return requirements.map(req => {
      const isValid = req.validator(password);
      return {
        ...req,
        valid: isValid,
        aria: `${isValid ? 'Met' : 'Not met'}: ${req.text}`
      };
    });
  }, [password, requirements]);

  return (
    <Box
      id="password-strength-requirements"
      mt={1}
      component="ul"
      aria-label="Password requirements"
      sx={{ listStyle: 'none', pl: 0, m: 0 }}
    >
      {reqs.map((req) => (
        <Box
          key={req.text.replace(/\s+/g, '-').toLowerCase()}
          component="li"
          display="flex"
          alignItems="center"
          gap={0.5}
          aria-label={req.aria}
        >
          {req.valid ?
            <CheckCircle
              fontSize="small"
              color="success"
              aria-hidden="true"
              aria-label="Requirement met" /> :
            <Cancel
              fontSize="small"
              color="error"
              aria-hidden="true"
              aria-label="Requirement not met" />
          }
          <Typography
            variant="caption"
            component="div"
            color={req.valid ? theme.palette.success.main : theme.palette.error.main}
            aria-invalid={!req.valid}
          >
            {req.text}
          </Typography>
        </Box>
      ))}
    </Box>
  );
};

const STRENGTH_CONFIG = [
  { label: 'Very Weak', icon: LockOpen, color: 'error' as const },
  { label: 'Weak', icon: LockOpen, color: 'error' as const },
  { label: 'Medium', icon: Lock, color: 'warning' as const },
  { label: 'Strong', icon: Security, color: 'info' as const },
  { label: 'Very Strong', icon: Security, color: 'success' as const }
];

/**
 * PasswordStrengthMeter component displays a visual indicator of password strength.
 * Uses zxcvbn for password strength estimation and MUI LinearProgress for visualization.
 */
const PasswordStrengthMeter: React.FC<PasswordStrengthMeterProps> = ({
  password,
  requirements,
  onStrengthChange,
  onError,
  focusable = true
}) => {
  const [debouncedPassword, setDebouncedPassword] = useState(password);
  const theme = useTheme();
  
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedPassword(password);
    }, 500);
    
    return () => clearTimeout(handler);
  }, [password]);
  
  interface ZxcvbnResult {
    score: number;
    feedback: {
      warning: string;
      suggestions: string[];
    };
    crack_times_display: {
      offline_slow_hashing_1e4_per_second: string;
    };
  }

  const testResult = useMemo((): ZxcvbnResult => {
    if (!debouncedPassword) return {
      score: 0,
      feedback: { warning: '', suggestions: [] },
      crack_times_display: { offline_slow_hashing_1e4_per_second: '' }
    };
    
    // Lazy load zxcvbn only when needed
    try {
      if (!(window as unknown as { zxcvbn?: unknown }).zxcvbn) {
        // Dynamically import zxcvbn only when needed
        import('zxcvbn').then((module) => {
          (window as unknown as { zxcvbn?: unknown }).zxcvbn = module.default;
        });
        return {
          score: 0,
          feedback: { warning: '', suggestions: [] },
          crack_times_display: { offline_slow_hashing_1e4_per_second: '' }
        };
      }
      const zxcvbn = (window as unknown as { zxcvbn?: (password: string) => unknown }).zxcvbn;
      const result = zxcvbn ? zxcvbn(debouncedPassword) : {
        score: 0,
        feedback: { warning: '', suggestions: [] },
        crack_times_display: { offline_slow_hashing_1e4_per_second: '' }
      };
      return result as ZxcvbnResult;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Password strength evaluation failed:', error);
      }
      if (onError) onError(error as Error);
      return {
        score: 0,
        feedback: { warning: 'Evaluation error', suggestions: [] },
        crack_times_display: { offline_slow_hashing_1e4_per_second: '' }
      };
    }
  }, [debouncedPassword, onError]);
  
  const strength = testResult.score;
  
  useEffect(() => {
    if (onStrengthChange) {
      onStrengthChange(strength);
    }
  }, [strength, onStrengthChange]);
  const { label, icon: StrengthIcon, color } = STRENGTH_CONFIG[strength];
  
  const formatCrackTime = (time: string) => {
    return time.replace(/(\d+ (?:second|minute|hour|day|month|year)s?)/, '$1 to crack')
              .replace('centuries', 'centuries to crack');
  };
  
  return (
    <Collapse in={password.length > 0} timeout={300}>
      <Box
        sx={{
          width: '100%',
          mt: 1,
          ...(focusable && {
            '&:focus': {
              outline: `2px solid ${theme.palette.primary.main}`,
              outlineOffset: '2px',
              borderRadius: '4px'
            }
          })
        }}
        aria-live="polite"
        role="region"
        aria-labelledby="password-strength-heading"
        tabIndex={focusable && password.length > 0 ? 0 : undefined}
      >
        <Box id="password-strength-heading" sx={visuallyHidden}>
          Password Strength Indicator
        </Box>
        
        <Box display="flex" alignItems="center" gap={1} mb={0.5}>
          <StrengthIcon fontSize="small" color={color} aria-hidden="true" />
          <LinearProgress
            variant="determinate"
            value={(strength + 1) * 20}
            color={color}
            sx={{
              flexGrow: 1,
              height: 8,
              borderRadius: 4,
              background: theme.palette.mode === 'light'
                ? 'linear-gradient(90deg, #f44336 0%, #e65100 25%, #f57c00 50%, #2e7d32 75%, #2e7d32 100%)'
                : undefined,
              [`& .MuiLinearProgress-bar`]: {
                borderRadius: 4,
                background: theme.palette.mode === 'dark'
                  ? 'linear-gradient(90deg, #f44336 0%, #e65100 25%, #f57c00 50%, #2e7d32 75%, #2e7d32 100%)'
                  : undefined,
                backgroundImage: strength < 2 ?
                  'repeating-linear-gradient(45deg, transparent, transparent 2px, rgba(255,255,255,0.3) 2px, rgba(255,255,255,0.3) 4px)' :
                  strength === 2 ?
                  'repeating-linear-gradient(-45deg, transparent, transparent 2px, rgba(255,255,255,0.3) 2px, rgba(255,255,255,0.3) 4px)' :
                  undefined
              }
            }}
            data-testid="password-strength-meter"
            role="progressbar"
            aria-valuenow={(strength + 1) * 20}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuetext={`Password strength: ${label}`}
            aria-labelledby="password-strength-label"
            aria-describedby="password-strength-requirements"
          />
          <Typography
            variant="caption"
            component="span"
            aria-hidden="true"
            sx={{
              minWidth: '80px',
              fontWeight: 'bold',
              color: theme.palette[color].main
            }}
          >
            {label}
          </Typography>
        </Box>
        <Box sx={visuallyHidden} aria-live="polite" role="status">
          Current password strength: {label}
        </Box>

        {password && strength < 4 && (
          <Box
            mt={2}
            p={1.5}
            bgcolor={theme.palette.background.paper}
            borderRadius={1}
            role="region"
            aria-labelledby="password-feedback-heading"
          >
            <Typography
              variant="body2"
              fontWeight="medium"
              id="password-feedback-heading"
            >
              <HelpOutlineIcon fontSize="small" sx={{ mr: 1, verticalAlign: 'middle' }} />
              Password Feedback
            </Typography>
            
            {testResult.feedback.warning && (
              <Box display="flex" alignItems="flex-start">
                <Typography variant="caption" color="warning.main" component="div" fontWeight="bold" mr={1}>
                  ⚠️
                </Typography>
                <Typography variant="caption" component="div">
                  {testResult.feedback.warning}
                </Typography>
              </Box>
            )}
            
            {testResult.feedback.suggestions.length > 0 && (
              <Box component="ul" sx={{ pl: 2, mt: 0.5, mb: 0 }}>
                {testResult.feedback.suggestions.map((suggestion: string, i: number) => (
                  <Typography variant="caption" component="li" key={i}>
                    {suggestion}
                  </Typography>
                ))}
              </Box>
            )}
            
            <Typography variant="caption" color="textSecondary" mt={1} display="block">
              Estimated cracking time: {formatCrackTime(testResult.crack_times_display.offline_slow_hashing_1e4_per_second.toString())}
            </Typography>
          </Box>
        )}

        <PasswordRequirements password={password} requirements={requirements} />
      </Box>
    </Collapse>
  );
};

export default React.memo(PasswordStrengthMeter);
