# Healthcare Management System - Backend

## Overview

Node.js backend for healthcare management system with Express, TypeScript, and PostgreSQL. Implements RESTful API with JWT authentication.

## Dashboard Endpoints

The backend provides the following dashboard endpoints:

- `GET /dashboard/patient-metrics` - Patient statistics
- `GET /dashboard/appointment-metrics` - Appointment tracking
- `GET /dashboard/system-metrics` - System health monitoring

### Implementation Details

- Metrics calculated in real-time using PostgreSQL window functions
- Data anonymization for HIPAA compliance
- Caching layer for frequent queries

## Getting Started

1. Install dependencies: `npm install`
2. Configure environment variables (copy .env.example to .env)
3. Run migrations: `npm run migrate`
4. Start server: `npm run dev`

## Configuration

### Trust Proxy Setting

The `TRUST_PROXY_COUNT` environment variable configures how many reverse proxies are in front of the Express application. This is important for IP-based rate limiting and security features to correctly identify client IP addresses.

- Default value: `1` (single load balancer)
- In production environments, adjust this value based on your infrastructure setup
- Set to `0` if running directly without any reverse proxies

## Directory Structure

- `src/` - Source code
  - `routes/` - API endpoints
  - `services/` - Business logic
  - `entities/` - Database models
  - `middlewares/` - Request processing
- `tests/` - Integration and unit tests
