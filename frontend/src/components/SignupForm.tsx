import {
  memo,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from 'react';
import { useNavigate } from 'react-router-dom';
import FormControl from '@mui/material/FormControl';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import CircularProgress from '@mui/material/CircularProgress';
import FormHelperText from '@mui/material/FormHelperText';
import OutlinedInput from '@mui/material/OutlinedInput';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Link from '@mui/material/Link';
import InputAdornment from '@mui/material/InputAdornment';
import IconButton from '@mui/material/IconButton';
import InputLabel from '@mui/material/InputLabel';
import CheckCircleOutline from '@mui/icons-material/CheckCircleOutline';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { AuthService } from '../services/authService';
import PasswordStrengthMeter from './PasswordStrengthMeter';
import { validatePassword } from '../constants/passwordRequirements';
import { ErrorDisplay } from './common/ErrorDisplay';

const MemoizedPasswordStrengthMeter = memo(PasswordStrengthMeter);

export function SignupForm() {
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    dateOfBirth: '',
    confirmPassword: '',
    acceptedTerms: false,
  });

  useEffect(() => {
    if (
      formData.confirmPassword &&
      formData.password !== formData.confirmPassword
    ) {
      setUiState((prev) => ({
        ...prev,
        errors: {
          ...prev.errors,
          confirmPassword: 'Passwords do not match',
        },
      }));
    } else if (uiState.errors.confirmPassword) {
      setUiState((prev) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { confirmPassword, ...restErrors } = prev.errors;
        return { ...prev, errors: restErrors };
      });
    }
  }, [formData.password, formData.confirmPassword]);

  const [uiState, setUiState] = useState({
    errors: {} as Record<string, string>,
    passwordErrors: validatePassword(''),
    showPasswords: { password: false, confirm: false },
    status: 'idle' as 'idle' | 'submitting' | 'success' | 'error',
  });
  const [touched, setTouched] = useState({
    firstName: false,
    lastName: false,
    email: false,
    dateOfBirth: false,
    password: false,
    confirmPassword: false,
    terms: false,
  });

  const timeoutRef = useRef<NodeJS.Timeout | null>(null);
  const navigate = useNavigate();

  const firstNameId = useId();
  const lastNameId = useId();
  const emailId = useId();
  const dobId = useId();
  const passwordId = useId();
  const confirmPasswordId = useId();
  const passwordErrorId = useId();

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const togglePasswordVisibility = (field: 'password' | 'confirm') =>
    setUiState((prev) => ({
      ...prev,
      showPasswords: {
        ...prev.showPasswords,
        [field]: !prev.showPasswords[field],
      },
    }));

  const handlePasswordChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const pwd = e.target.value;
      setFormData((prev) => ({ ...prev, password: pwd }));

      if (timeoutRef.current) clearTimeout(timeoutRef.current);

      timeoutRef.current = setTimeout(() => {
        setUiState((prev) => ({
          ...prev,
          passwordErrors: validatePassword(pwd),
        }));
      }, 300);
    },
    []
  );

  const validateForm = () => {
    const newErrors: Record<string, string> = {};
    const today = new Date().toISOString().split('T')[0];

    if (!formData.firstName.trim())
      newErrors.firstName = 'First name is required';
    if (!formData.lastName.trim())
      newErrors.lastName = 'Last name is required';

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Invalid email format';
    }

    if (!formData.dateOfBirth) {
      newErrors.dateOfBirth = 'Date of birth is required';
    } else if (formData.dateOfBirth > today) {
      newErrors.dateOfBirth = 'Date cannot be in the future';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (uiState.passwordErrors.length > 0) {
      newErrors.password = 'Password does not meet requirements';
    }

    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Confirm password is required';
    } else if (
      formData.password &&
      formData.password !== formData.confirmPassword
    ) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    if (!formData.acceptedTerms) {
      newErrors.terms = 'You must accept the Terms of Service';
    }

    return newErrors;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const newErrors = validateForm();

    if (Object.keys(newErrors).length > 0) {
      setUiState((prev) => ({ ...prev, errors: newErrors }));
      return;
    }

    setUiState((prev) => ({ ...prev, status: 'submitting' }));

    try {
      await AuthService.signup({
        firstName: formData.firstName,
        lastName: formData.lastName,
        email: formData.email,
        password: formData.password,
        dateOfBirth: formData.dateOfBirth,
      });
      navigate('/login');
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Registration failed';
      setUiState((prev) => ({
        ...prev,
        status: 'error',
        errors: { ...prev.errors, form: message },
      }));
    }
  };

  return (
    <Paper
      elevation={3}
      sx={{ maxWidth: 400, mx: 'auto', mt: 1, p: 4 }}
      component='article'
      aria-labelledby='signup-form-title'
    >
      <Typography
        id='signup-form-title'
        variant='h5'
        component='h2'
        gutterBottom
        align='center'
      >
        Create New Account
      </Typography>

      {uiState.errors.form && (
        <ErrorDisplay
          message={uiState.errors.form}
          severity='error'
          sx={{ mb: 2 }}
        />
      )}

      <Box
        component='form'
        onSubmit={handleSubmit}
        sx={{ mt: 2 }}
        aria-describedby={
          uiState.errors.form ? 'form-error' : undefined
        }
      >
        <Box sx={{ display: 'flex', gap: '16px' }}>
          <FormControl
            fullWidth
            margin='normal'
            error={!!uiState.errors.firstName}
          >
            <InputLabel
              htmlFor={firstNameId}
              required
            >
              First Name
            </InputLabel>
            <OutlinedInput
              id={firstNameId}
              label='First Name'
              value={formData.firstName}
              onChange={(e) =>
                setFormData((prev) => ({
                  ...prev,
                  firstName: e.target.value,
                }))
              }
              onBlur={() =>
                setTouched((prev) => ({ ...prev, firstName: true }))
              }
              aria-required='true'
              aria-describedby={
                uiState.errors.firstName
                  ? `first-name-error ${firstNameId}-reqs`
                  : undefined
              }
              aria-errormessage={
                uiState.errors.firstName
                  ? 'first-name-error'
                  : undefined
              }
              inputProps={{
                'aria-describedby': `${firstNameId}-reqs`,
              }}
              required
            />
            {uiState.errors.firstName && (
              <FormHelperText id='first-name-error'>
                {uiState.errors.firstName}
              </FormHelperText>
            )}
          </FormControl>
          <FormControl
            fullWidth
            margin='normal'
            error={!!uiState.errors.lastName}
          >
            <InputLabel
              htmlFor={lastNameId}
              required
            >
              Last Name
            </InputLabel>
            <OutlinedInput
              id={lastNameId}
              label='Last Name'
              value={formData.lastName}
              onChange={(e) =>
                setFormData((prev) => ({
                  ...prev,
                  lastName: e.target.value,
                }))
              }
              onBlur={() =>
                setTouched((prev) => ({ ...prev, lastName: true }))
              }
              aria-required='true'
              aria-describedby={
                uiState.errors.lastName
                  ? 'last-name-error'
                  : undefined
              }
              required
            />
            {uiState.errors.lastName && (
              <FormHelperText id='last-name-error'>
                {uiState.errors.lastName}
              </FormHelperText>
            )}
          </FormControl>
        </Box>

        <FormControl
          fullWidth
          margin='normal'
          error={!!uiState.errors.email}
        >
          <InputLabel
            htmlFor={emailId}
            required
          >
            Email
          </InputLabel>
          <OutlinedInput
            id={emailId}
            label='Email'
            type='email'
            value={formData.email}
            onChange={(e) =>
              setFormData((prev) => ({
                ...prev,
                email: e.target.value,
              }))
            }
            onBlur={() =>
              setTouched((prev) => ({ ...prev, email: true }))
            }
            aria-required='true'
            aria-describedby={
              uiState.errors.email ? 'email-error' : undefined
            }
            required
            inputProps={{
              autoComplete: 'email',
            }}
          />
          {uiState.errors.email && (
            <FormHelperText id='email-error'>
              {uiState.errors.email}
            </FormHelperText>
          )}
        </FormControl>

        <FormControl
          fullWidth
          margin='normal'
          error={!!uiState.errors.dateOfBirth}
        >
          <InputLabel
            htmlFor={dobId}
            shrink
            required
          >
            Date of Birth
          </InputLabel>
          <OutlinedInput
            id={dobId}
            label='Date of Birth'
            notched={true}
            type='date'
            value={formData.dateOfBirth}
            onChange={(e) =>
              setFormData((prev) => ({
                ...prev,
                dateOfBirth: e.target.value,
              }))
            }
            onBlur={() =>
              setTouched((prev) => ({ ...prev, dateOfBirth: true }))
            }
            placeholder='YYYY-MM-DD'
            aria-required='true'
            aria-describedby={
              uiState.errors.dateOfBirth ? 'dob-error' : undefined
            }
            inputProps={{
              max: new Date().toISOString().split('T')[0],
            }}
            required
          />
          {uiState.errors.dateOfBirth && (
            <FormHelperText
              id='dob-error'
              error
            >
              {uiState.errors.dateOfBirth}
            </FormHelperText>
          )}
        </FormControl>

        <FormControl
          fullWidth
          margin='normal'
          error={
            (touched.password && uiState.passwordErrors.length > 0) ||
            (touched.password && !!uiState.errors.password)
          }
        >
          <InputLabel
            htmlFor={passwordId}
            required
          >
            Password
          </InputLabel>
          <OutlinedInput
            id={passwordId}
            label='Password'
            type={
              uiState.showPasswords.password ? 'text' : 'password'
            }
            value={formData.password}
            onChange={handlePasswordChange}
            onBlur={() =>
              setTouched((prev) => ({ ...prev, password: true }))
            }
            autoComplete='new-password'
            inputProps={{
              'aria-describedby': `password-strength-requirements ${passwordErrorId}`,
              'aria-errormessage': uiState.errors.password
                ? passwordErrorId
                : undefined,
              autoComplete: 'new-password',
            }}
            endAdornment={
              <InputAdornment position='end'>
                <IconButton
                  onClick={() => togglePasswordVisibility('password')}
                  edge='end'
                  aria-label={
                    uiState.showPasswords.password
                      ? 'Hide password'
                      : 'Show password'
                  }
                  aria-controls={passwordId}
                >
                  {uiState.showPasswords.password ? (
                    <VisibilityOff />
                  ) : (
                    <Visibility />
                  )}
                </IconButton>
              </InputAdornment>
            }
            required
            aria-required='true'
          />
          <FormHelperText id={passwordErrorId}>
            {uiState.errors.password && (
              <span>{uiState.errors.password}</span>
            )}
          </FormHelperText>
        </FormControl>

        <Box
          aria-live='polite'
          aria-atomic='true'
          sx={{ mt: 1 }}
        >
          <MemoizedPasswordStrengthMeter
            password={formData.password}
          />
        </Box>

        <FormControl
          fullWidth
          margin='normal'
          error={
            touched.confirmPassword &&
            !!uiState.errors.confirmPassword
          }
          variant='outlined'
        >
          <InputLabel
            htmlFor={confirmPasswordId}
            required
          >
            Confirm Password
          </InputLabel>
          <OutlinedInput
            id={confirmPasswordId}
            label='Confirm Password'
            type={uiState.showPasswords.confirm ? 'text' : 'password'}
            value={formData.confirmPassword}
            onChange={(
              e: React.ChangeEvent<
                HTMLInputElement | HTMLTextAreaElement
              >
            ) =>
              setFormData((prev) => ({
                ...prev,
                confirmPassword: e.target.value,
              }))
            }
            onBlur={() =>
              setTouched((prev) => ({
                ...prev,
                confirmPassword: true,
              }))
            }
            aria-required='true'
            inputProps={{
              'aria-describedby': uiState.errors.confirmPassword
                ? 'confirm-error'
                : undefined,
              autoComplete: 'new-password',
            }}
            endAdornment={
              <InputAdornment position='end'>
                <IconButton
                  onClick={() => togglePasswordVisibility('confirm')}
                  edge='end'
                  aria-label={
                    uiState.showPasswords.confirm
                      ? 'Hide password'
                      : 'Show password'
                  }
                  aria-controls={confirmPasswordId}
                >
                  {uiState.showPasswords.confirm ? (
                    <VisibilityOff />
                  ) : (
                    <Visibility />
                  )}
                </IconButton>
              </InputAdornment>
            }
            required
            aria-invalid={!!uiState.errors.confirmPassword}
          />
          {uiState.errors.confirmPassword ? (
            <FormHelperText
              id='confirm-error'
              error
            >
              {uiState.errors.confirmPassword}
            </FormHelperText>
          ) : formData.confirmPassword &&
            formData.password === formData.confirmPassword ? (
            <FormHelperText
              id='confirm-success'
              sx={{ color: 'success.main' }}
            >
              <CheckCircleOutline
                sx={{
                  fontSize: '1rem',
                  verticalAlign: 'middle',
                  mr: 0.5,
                }}
              />
              Passwords match
            </FormHelperText>
          ) : null}
        </FormControl>

        {/* Terms of Service */}
        <FormControl
          required
          error={touched.terms && !!uiState.errors.terms}
          component='fieldset'
          sx={{ mt: 2, ml: 1 }}
        >
          <FormControlLabel
            control={
              <Checkbox
                checked={formData.acceptedTerms}
                onChange={(e) =>
                  setFormData((prev) => ({
                    ...prev,
                    acceptedTerms: e.target.checked,
                  }))
                }
                onBlur={() =>
                  setTouched((prev) => ({ ...prev, terms: true }))
                }
                slotProps={{
                  input: {
                    'aria-required': 'true',
                    'aria-describedby': uiState.errors.terms
                      ? 'terms-error'
                      : undefined,
                  },
                }}
              />
            }
            label={
              <Typography variant='body2'>
                I agree to the{' '}
                <Link
                  href='/terms'
                  target='_blank'
                  rel='noopener noreferrer'
                >
                  Terms of Service
                </Link>
              </Typography>
            }
          />
          {uiState.errors.terms && (
            <FormHelperText
              id='terms-error'
              error
            >
              {uiState.errors.terms}
            </FormHelperText>
          )}
        </FormControl>

        <Button
          fullWidth
          variant='contained'
          type='submit'
          sx={{ mt: 3 }}
          disabled={
            uiState.status === 'submitting' ||
            uiState.status === 'success'
          }
        >
          {uiState.status === 'submitting' ? (
            <CircularProgress
              size={24}
              color='inherit'
            />
          ) : uiState.status === 'success' ? (
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <CheckCircleOutline sx={{ mr: 1 }} />
              Account Created!
            </Box>
          ) : (
            'Create Account'
          )}
        </Button>

        {uiState.status === 'success' && (
          <Box
            sx={{
              mt: 2,
              p: 2,
              bgcolor: 'success.light',
              borderRadius: 1,
              display: 'flex',
              alignItems: 'center',
            }}
          >
            <CheckCircleOutline
              sx={{ mr: 1, color: 'success.main' }}
            />
            <Typography color='success.main'>
              Account created successfully! Redirecting to login...
            </Typography>
          </Box>
        )}

        <Typography
          variant='body2'
          sx={{ mt: 2 }}
          align='center'
        >
          Already have an account?{' '}
          <Link
            href='/login'
            underline='hover'
            aria-label='Navigate to login page'
          >
            Login here
          </Link>
        </Typography>
      </Box>
    </Paper>
  );
}
