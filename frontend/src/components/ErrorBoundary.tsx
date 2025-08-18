import React from 'react';
import { getErrorMessage } from '../utils/errorUtils';

export interface ErrorBoundaryFallbackProps {
  resetErrorBoundary: () => void;
  errorMessage: string;
}

interface ErrorBoundaryProps {
  fallback: React.ReactNode | ((props: ErrorBoundaryFallbackProps) => React.ReactNode);
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  resetErrorBoundary = () => {
    this.setState({ hasError: false, error: undefined });
  };

  render() {
    if (this.state.hasError) {
      const errorMessage = this.state.error ? getErrorMessage(this.state.error) : 'An unknown error occurred';
      
      if (typeof this.props.fallback === 'function') {
        return this.props.fallback({ resetErrorBoundary: this.resetErrorBoundary, errorMessage });
      } else if (this.props.fallback) {
        return this.props.fallback;
      }
      
      return (
        <div>
          <h2>Application Error</h2>
          <p>{errorMessage}</p>
          <button onClick={this.resetErrorBoundary}>Try again</button>
        </div>
      );
    }
    return this.props.children;
  }
}