# Healthcare Management System

A comprehensive healthcare management system with patient records, authentication, and dashboard functionality. This full-stack application features a React/TypeScript frontend and a Node.js/Express backend with PostgreSQL database integration.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Environment Configuration](#environment-configuration)
- [Database Setup](#database-setup)
- [Running the Application](#running-the-application)
- [Testing](#testing)
- [API Documentation](#api-documentation)
- [Security](#security)
- [Deployment](#deployment)
- [Containerization](#containerization)
- [Important Files](#important-files)
- [Contributing](#contributing)
- [License](#license)

## Features

### Authentication & Authorization

- JWT-based authentication with RS256 algorithm
- Role-Based Access Control (RBAC) with roles: patient, staff, admin, clinician
- Secure password handling with strength validation
- Session management with token refresh capabilities
- CSRF protection for all state-changing operations

### Patient Management

- Patient registration and profile management
- Medical history tracking with detailed records
- Patient data CRUD operations with validation
- Search and filtering capabilities

### Dashboard & Analytics

- Administrative dashboard with key metrics
- Patient statistics and analytics
- User activity monitoring
- Data visualization components

### Accessibility & Compliance

- WCAG 2.1 AA compliance
- Screen reader support
- Keyboard navigation
- Skip navigation links
- ARIA attributes for enhanced accessibility

## Architecture

The application follows a client-server architecture with a React frontend communicating with a Node.js backend through a RESTful API.

```
┌─────────────────┐    HTTP    ┌──────────────────┐    Database    ┌──────────────┐
│   React/TypeScript Frontend  │ ────────────→ │  Node.js/Express Backend  │ ────────────→ │  PostgreSQL  │
│                              │               │                       │               │            
└─────────────────┘           └──────────────────┘                   └──────────────┘
```

### Frontend Architecture

- Component-based architecture with React hooks
- Context API for state management
- Protected routes with authentication guards
- Service layer for API communication
- Material-UI components for UI elements

### Backend Architecture

- Modular route structure
- Middleware for authentication and validation
- TypeORM for database operations
- Service layer for business logic
- Comprehensive error handling

## Technology Stack

### Frontend

- React 18 with TypeScript
- Vite as build tool
- Material-UI (MUI) for UI components
- React Router for navigation
- Axios for HTTP requests
- Jest and React Testing Library for testing

### Backend

- Node.js with Express
- TypeScript
- PostgreSQL with TypeORM
- JWT for authentication
- Zod for validation
- Jest for testing

### Database

- PostgreSQL for primary data storage

### Security

- Helmet for HTTP headers security
- CORS configuration
- CSRF protection
- Rate limiting
- Input sanitization and validation

## Project Structure

```
.
├── backend/
│   ├── src/
│   │   ├── config/          # Configuration files
│   │   ├── controllers/     # Request handlers
│   │   ├── entities/        # Database entities
│   │   ├── errors/          # Custom error classes
│   │   ├── middlewares/     # Express middlewares
│   │   ├── routes/          # API route definitions
│   │   ├── schemas/         # Validation schemas
│   │   ├── services/        # Business logic
│   │   ├── utils/           # Utility functions
│   │   ├── data-source.ts   # Database connection
│   │   └── index.ts         # Application entry point
│   ├── tests/               # Test files
│   ├── scripts/             # Utility scripts
│   ├── docs/                # Documentation
│   ├── package.json
│   └── ...
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── contexts/        # React contexts
│   │   ├── hooks/           # Custom hooks
│   │   ├── pages/           # Page components
│   │   ├── services/        # API service layer
│   │   ├── types/           # TypeScript types
│   │   ├── utils/           # Utility functions
│   │   ├── constants/       # Application constants
│   │   ├── App.tsx          # Main application component
│   │   └── main.tsx         # Entry point
│   ├── tests/               # Test files
│   ├── scripts/             # Utility scripts
│   ├── package.json
│   └── ...
├── docs/                    # Project documentation
└── ...
```

## Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- PostgreSQL (v12 or higher)

## Installation

### Backend Setup

1. Navigate to the backend directory:

   ```bash
   cd backend
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

### Frontend Setup

1. Navigate to the frontend directory:

   ```bash
   cd frontend
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

## Environment Configuration

### Backend Environment Variables

Create a `.env` file in the `backend/` directory with the following variables:

```env
# Server Configuration
PORT=3001
NODE_ENV=development

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=your_username
DB_PASSWORD=your_password
DB_NAME=healthcare_db

# JWT Configuration
JWT_ACCESS_SECRET=your_access_secret_key
JWT_REFRESH_SECRET=your_refresh_secret_key
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# CSRF Configuration
CSRF_SECRET=your_csrf_secret

# CORS Configuration
CLIENT_URL=http://localhost:5173
```

### Frontend Environment Variables

Create a `.env` file in the `frontend/` directory with the following variables:

```env
# API Configuration
VITE_API_BASE_URL=http://localhost:3001
VITE_CLIENT_URL=http://localhost:5173
```

## Database Setup

1. Ensure PostgreSQL is running on your system
2. Create a new database:

   ```sql
   CREATE DATABASE healthcare_db;
   ```

3. The application will automatically create tables on first run using TypeORM synchronization

## Running the Application

### Start Backend Server

```bash
cd backend
npm run dev
```

The backend server will start on `http://localhost:3001`

### Start Frontend Application

```bash
cd frontend
npm run dev
```

The frontend application will start on `http://localhost:5173`

## Testing

### Backend Testing

Run the backend test suite:

```bash
cd backend
npm run test
```

Run tests with coverage:

```bash
npm run test:coverage
```

### Frontend Testing

Run the frontend test suite:

```bash
cd frontend
npm run test
```

Run tests with coverage:

```bash
npm run test:coverage
```

Run end-to-end tests:

```bash
npm run test:e2e
```

## API Documentation

### Authentication Endpoints

| Method | Endpoint | Description | Role Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/register` | Register new user | Public |
| POST | `/api/auth/login` | User login | Public |
| POST | `/api/auth/refresh` | Refresh access token | Public |
| POST | `/api/auth/logout` | User logout | Authenticated |

### Patient Endpoints

| Method | Endpoint | Description | Role Required |
|--------|----------|-------------|---------------|
| POST | `/api/patients` | Create new patient | Staff, Admin |
| GET | `/api/patients` | Get all patients | Staff, Admin, Clinician |
| GET | `/api/patients/:id` | Get patient by ID | Staff, Admin, Clinician, Patient (own) |
| PUT | `/api/patients/:id` | Update patient | Staff, Admin, Patient (own) |
| DELETE | `/api/patients/:id` | Delete patient | Admin |

### Medical History Endpoints

| Method | Endpoint | Description | Role Required |
|--------|----------|-------------|---------------|
| POST | `/api/medical-history` | Create medical history record | Staff, Admin, Clinician |
| GET | `/api/medical-history/patient/:patientId` | Get patient medical history | Staff, Admin, Clinician, Patient (own) |
| PUT | `/api/medical-history/:id` | Update medical history record | Staff, Admin, Clinician |
| DELETE | `/api/medical-history/:id` | Delete medical history record | Admin |

### Dashboard Endpoints

| Method | Endpoint | Description | Role Required |
|--------|----------|-------------|---------------|
| GET | `/api/dashboard/system-metrics` | Get dashboard system statistics | Admin |
| GET | `/api/dashboard/patient-metrics` | Get patient statistics | Admin |
| GET | `/api/dashboard/appointment-metrics` | Get appointments data | Admin |

## Security

### Authentication Flow

1. User registers or logs in
2. Server generates JWT access and refresh tokens
3. Access token is used for API authentication
4. Refresh token is used to obtain new access tokens
5. Tokens are validated using RS256 algorithm

### Role-Based Access Control

The system implements RBAC with the following roles:

- **Patient**: Can view and update their own information
- **Staff**: Can manage patient records
- **Clinician**: Can view patient records and medical history
- **Admin**: Full system access including user management

### Security Measures

- JWT tokens with RS256 algorithm
- CSRF protection for all state-changing requests
- Helmet for secure HTTP headers
- CORS configuration
- Rate limiting
- Input validation and sanitization
- Password strength requirements
- Secure password storage

## Deployment

### Production Build

#### Backend

```bash
cd backend
npm run build
npm start
```

#### Frontend

```bash
cd frontend
npm run build
```

The build output will be in the `dist/` directory.

### Environment for Production

Ensure all environment variables are properly set for production:

- Use strong secret keys
- Set `NODE_ENV=production`
- Configure proper database connection
- Set correct client and server URLs

## Important Files

### Backend

- [`backend/src/index.ts`](backend/src/index.ts): Main server entry point with security middleware
- [`backend/src/data-source.ts`](backend/src/data-source.ts): Database connection configuration
- [`backend/src/routes/authRoutes.ts`](backend/src/routes/authRoutes.ts): Authentication endpoints
- [`backend/src/middlewares/authMiddleware.ts`](backend/src/middlewares/authMiddleware.ts): JWT verification and RBAC
- [`backend/src/routes/patientRoutes.ts`](backend/src/routes/patientRoutes.ts): Patient management CRUD operations
- [`backend/src/routes/dashboardRoutes.ts`](backend/src/routes/dashboardRoutes.ts): Admin dashboard metrics
- [`backend/src/entities/Patient.ts`](backend/src/entities/Patient.ts): Patient entity definition
- [`backend/src/services/authService.ts`](backend/src/services/authService.ts): Authentication business logic
- [`backend/src/services/PatientService.ts`](backend/src/services/PatientService.ts): Patient business logic
- [`backend/src/config/permissions.ts`](backend/src/config/permissions.ts): RBAC permission definitions

### Frontend

- [`frontend/src/main.tsx`](frontend/src/main.tsx): Application entry point
- [`frontend/src/App.tsx`](frontend/src/App.tsx): Main application component with routing
- [`frontend/src/contexts/AuthContext.tsx`](frontend/src/contexts/AuthContext.tsx): Authentication state management
- [`frontend/src/services/apiRequest.ts`](frontend/src/services/apiRequest.ts): Secure API request service with CSRF protection
- [`frontend/src/services/authService.ts`](frontend/src/services/authService.ts): Authentication service functions
- [`frontend/src/components/LoginForm.tsx`](frontend/src/components/LoginForm.tsx): Login form component
- [`frontend/src/components/PatientList.tsx`](frontend/src/components/PatientList.tsx): Patient list component
- [`frontend/src/components/PatientForm.tsx`](frontend/src/components/PatientForm.tsx): Patient form component
- [`frontend/src/components/PatientDetailsView.tsx`](frontend/src/components/PatientDetailsView.tsx): Patient details view
- [`frontend/src/pages/DashboardPage.tsx`](frontend/src/pages/DashboardPage.tsx): Admin dashboard page

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

Please ensure your code follows the project's coding standards and includes appropriate tests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
