import type { JSX } from 'react';
import {
  BrowserRouter as Router,
  Route,
  Routes,
  Navigate,
  useLocation,
} from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CssBaseline, Container, CircularProgress, Box } from '@mui/material';
import { LoginForm } from './components/LoginForm';
import { SignupForm } from './components/SignupForm';
import { TermsOfServicePage } from './components/TermsOfServicePage';
import './App.css';
import { AuthProvider } from './contexts/AuthContext';
import { useAuth } from './hooks/useAuth';
import { ThemeProvider } from './contexts/ThemeContext';
import AppHeader from './components/AppHeader/AppHeader';
import BottomNavigationMenu from './components/AppHeader/BottomNavigation';
import React from 'react';

// Lazy load components
const DashboardPage = React.lazy(() => import('./pages/DashboardPage').then(module => ({ default: module.DashboardPage })));
const PatientList = React.lazy(() => import('./components/PatientList').then(module => ({ default: module.PatientList })));
const PatientDetailsView = React.lazy(() => import('./components/PatientDetailsView').then(module => ({ default: module.PatientDetailsView })));

const queryClient = new QueryClient();

const PrivateRoute = ({ children, allowedRoles }: { children: JSX.Element; allowedRoles?: string[] }) => {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();

  if (!isAuthenticated && !isLoading) {
    return <Navigate to="/login" replace />;
  }

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    if (user.role === 'patient') {
      // Prevent infinite loop: only redirect if not already on patient profile
      const isOnPatientProfile = location.pathname.startsWith('/patients/me');
      return isOnPatientProfile ? children : <Navigate to="/patients/me" replace />;
    }
    return <Navigate to="/" replace />;
  }

  return children;
};
const ProtectedAuthRoute = ({ children }: { children: JSX.Element }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (isAuthenticated) {
    // Check if user is on patient profile page to avoid infinite redirect
    const user = JSON.parse(localStorage.getItem('authState') || '{}');
    if (user && user.role === 'patient') {
      return <Navigate to="/patients/me" replace />;
    }
    return <Navigate to="/" replace />;
  }

  return children;
};


const AppRoutes = () => {
  const { isLoading } = useAuth();
  
  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress size={60} />
      </Box>
    );
  }
  
  return (
    <>
      <AppHeader />
      <Container
        maxWidth='xl'
        sx={{ py: 4 }}
      >
        <Routes>
          <Route
            path="/login"
            element={<ProtectedAuthRoute><LoginForm /></ProtectedAuthRoute>}
          />
          <Route
            path="/signup"
            element={<ProtectedAuthRoute><SignupForm /></ProtectedAuthRoute>}
          />
          <Route path="/terms" element={<TermsOfServicePage />} />
          
          <Route
            path='/'
            element={
              <PrivateRoute allowedRoles={['clinician','admin', 'staff']}>
                <React.Suspense fallback={
                  <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
                    <CircularProgress size={60} />
                  </Box>
                }>
                  <PatientList />
                </React.Suspense>
              </PrivateRoute>
            }
          />
          <Route
            path='/dashboard'
            element={
              <PrivateRoute allowedRoles={['admin']}>
                <React.Suspense fallback={
                  <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
                    <CircularProgress size={60} />
                  </Box>
                }>
                  <DashboardPage />
                </React.Suspense>
              </PrivateRoute>
            }
          />
          <Route
            path='/patients/:id'
            element={
              <PrivateRoute allowedRoles={['clinician','admin', 'staff']}>
                <React.Suspense fallback={
                  <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
                    <CircularProgress size={60} />
                  </Box>
                }>
                  <PatientDetailsView />
                </React.Suspense>
              </PrivateRoute>
            }
          />
        </Routes>
      </Container>
      <BottomNavigationMenu />
    </>
  );
};

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <QueryClientProvider client={queryClient}>
          <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <CssBaseline />
            <AppRoutes />
          </Router>
        </QueryClientProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}
export default App;
