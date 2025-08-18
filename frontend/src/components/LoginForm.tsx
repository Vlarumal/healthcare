import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import type { User } from '../types/auth';
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import Paper from '@mui/material/Paper'
import Link from '@mui/material/Link'
import InputAdornment from '@mui/material/InputAdornment'
import IconButton from '@mui/material/IconButton'
import TextField from '@mui/material/TextField';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { GuestLoginButtons } from './GuestLoginButtons';
import { ErrorDisplay } from './common/ErrorDisplay';

export function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState({
    email: '',
    password: '',
    form: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loginSuccess, setLoginSuccess] = useState(false);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const navigate = useNavigate();
  const { login, isLoading, isAuthenticated } = useAuth();
  
  useEffect(() => {
    if (loginSuccess && currentUser) {
      if (currentUser.role === 'patient') {
        navigate('/patients/me', { replace: true });
      } else {
        navigate('/', { replace: true });
      }
      setLoginSuccess(false);
      setCurrentUser(null);
    }
  }, [loginSuccess, currentUser, navigate]);
  
  useEffect(() => {
    if (isAuthenticated) {
      const user = JSON.parse(localStorage.getItem('authState') || '{}');
      if (user && user.role === 'patient') {
        navigate('/patients/me', { replace: true });
      } else if (user) {
        navigate('/', { replace: true });
      }
    }
  }, [isAuthenticated, navigate]);

  const validateEmail = (email: string) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setErrors(prev => ({ ...prev, email: 'Please enter a valid email address' }));
      return false;
    }
    setErrors(prev => ({ ...prev, email: '' }));
    return true;
  };

  const validatePassword = (password: string) => {
    if (password.length < 8) {
      setErrors(prev => ({ ...prev, password: 'Please enter a valid password' }));
      return false;
    } else if (!/[A-Z]/.test(password)) {
      setErrors(prev => ({ ...prev, password: 'Please enter a valid password' }));
      return false;
    } else if (!/\d/.test(password)) {
      setErrors(prev => ({ ...prev, password: 'Please enter a valid password' }));
      return false;
    } else if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      setErrors(prev => ({ ...prev, password: 'Please enter a valid password' }));
      return false;
    }

    setErrors(prev => ({ ...prev, password: '' }));
    return true;
  };
  const togglePasswordVisibility = () => setShowPassword(!showPassword);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    setErrors(prev => ({ ...prev, form: '' }));

    let hasEmptyField = false;
    if (!email.trim()) {
      setErrors(prev => ({ ...prev, email: 'Email is required' }));
      hasEmptyField = true;
    }
    if (!password) {
      setErrors(prev => ({ ...prev, password: 'Password is required' }));
      hasEmptyField = true;
    }
    if (hasEmptyField) {
      return;
    }

    const isEmailValid = validateEmail(email);
    const isPasswordValid = validatePassword(password);
    
    if (!isEmailValid || !isPasswordValid) {
      return;
    }

    try {
      const currentUser = await login(email, password);
      setCurrentUser(currentUser);
      setLoginSuccess(true);
    } catch (err) {
      setErrors(prev => ({ ...prev, form: 'Authentication failed. Please check your credentials.' }));
      if (import.meta.env.DEV) {
        console.error('Login error:', err);
      }
    }
  };

  return (
    <Paper
      elevation={3}
      sx={{
        maxWidth: 400,
        mx: 'auto',
        mt: (theme) => theme.spacing(8),
        p: (theme) => theme.spacing(4)
      }}
      aria-label="Login form"
    >
      <Typography
        variant='h5'
        component='h2'
        gutterBottom
        align='center'
      >
        Healthcare System Login
      </Typography>
      {errors.form && (
        <ErrorDisplay
          message={errors.form}
          severity="error"
          sx={{ mb: 2 }}
        />
      )}

      <Box
        component='form'
        onSubmit={handleSubmit}
        sx={{ mt: 2 }}
        aria-label="Login form"
      >
        <TextField
          fullWidth
          margin='normal'
          label='Email'
          variant='outlined'
          type='email'
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
            validateEmail(e.target.value);
          }}
          error={!!errors.email}
          disabled={isLoading}
          slotProps={{
            htmlInput: {
              'aria-invalid': !!errors.email,
              'aria-describedby': errors.email ? 'email-error' : undefined,
              autoComplete: "email"
            }
          }}
        />
        {errors.email && (
          <ErrorDisplay
            id='email-error'
            message={errors.email}
            severity="error"
            sx={{ mt: 1 }}
          />
        )}

        <TextField
          fullWidth
          margin='normal'
          label='Password'
          variant='outlined'
          type={showPassword ? 'text' : 'password'}
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            validatePassword(e.target.value);
          }}
          error={!!errors.password}
          disabled={isLoading}
          slotProps={{
            input: {
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    onClick={togglePasswordVisibility}
                    edge="end"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    disabled={isLoading}
                    sx={{
                      '&:focus-visible': {
                        outline: (theme) => `2px solid ${theme.palette.primary.main}`,
                        outlineOffset: '2px'
                      }
                    }}
                  >
                    {showPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              ),
            },
            htmlInput: {
              'aria-invalid': !!errors.password,
              'aria-describedby': errors.password ? 'password-error' : undefined,
              autoComplete: "current-password"
            }
          }}
        />
        {errors.password && (
          <ErrorDisplay
            id='password-error'
            message={errors.password}
            severity="error"
            sx={{ mt: 1 }}
          />
        )}

        {/* <Typography variant='body2' sx={{ mt: 1 }} align='right'>
          <Link
            href='/forgot-password'
            underline='hover'
            variant='body2'
          >
            Forgot Password?
          </Link>
        </Typography> */}

        <Button
          fullWidth
          variant='contained'
          type='submit'
          sx={{ mt: (theme) => theme.spacing(3) }}
          disabled={isLoading}
        >
          {isLoading ? 'Signing In...' : 'Login'}
        </Button>

        <Typography
          variant='body2'
          sx={{ mt: (theme) => theme.spacing(2) }}
          align='center'
        >
          Don't have an account?{' '}
          <Link
            href='/signup'
            underline='hover'
            variant='body2'
          >
            Sign Up
          </Link>
        </Typography>

        {/* Temporary Guest Login for Demo */}
        <GuestLoginButtons disabled={isLoading} />
      </Box>
    </Paper>
  );
}
