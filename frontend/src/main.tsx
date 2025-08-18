// import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { ErrorBoundary } from './components/ErrorBoundary'
import { setupApiInterceptors } from './services/apiRequest'
import { logout } from './services/logoutService'

setupApiInterceptors(logout);

createRoot(document.getElementById('root')!).render(
  // <StrictMode>
    <ErrorBoundary fallback={<div style={{ padding: 20 }}>Application Error - Please refresh the page</div>}>
      <App />
    </ErrorBoundary>
  // </StrictMode>,
);
