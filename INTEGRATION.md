# Frontend-Backend Integration Guide

## Overview
This guide outlines the integration points between the frontend and backend components of the AWS Cloud Misconfiguration Scanner.

## Architecture Overview

### Backend Services
- FastAPI backend server
- AWS Boto3 integration
- Async task processing
- WebSocket for real-time updates

### Frontend Components
- Next.js frontend application
- React Query for data management
- WebSocket client for live updates

## API Integration Points

### 1. Authentication & Authorization
```typescript
// Frontend implementation
interface AuthRequest {
  username: string;
  password: string;
}

interface AuthResponse {
  access_token: string;
  token_type: string;
}

// API Endpoints
POST /api/auth/login
POST /api/auth/refresh
POST /api/auth/logout
```

### 2. AWS Service Scanning
```typescript
// Scan Configuration
interface ScanConfig {
  services: string[];
  regions: string[];
  scan_depth: 'quick' | 'deep';
}

// API Endpoints
POST /api/scan/start
GET /api/scan/{scan_id}/status
GET /api/scan/{scan_id}/results
```

### 3. Dashboard Data
```typescript
// Dashboard Metrics
interface DashboardMetrics {
  total_resources: number;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  scan_history: ScanHistoryItem[];
}

// API Endpoints
GET /api/dashboard/metrics
GET /api/dashboard/trends
```

### 4. Service-Specific Data
```typescript
// Resource Configuration
interface ResourceConfig {
  resource_id: string;
  service: string;
  configuration: Record<string, any>;
  issues: Issue[];
}

// API Endpoints
GET /api/services/{service}/resources
GET /api/services/{service}/issues
```

## WebSocket Integration

### Connection Setup
```typescript
// Frontend WebSocket initialization
const socket = new WebSocket(`ws://${API_URL}/ws`);

socket.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // Handle different message types
  switch(data.type) {
    case 'scan_progress':
      updateScanProgress(data.progress);
      break;
    case 'new_issue':
      addNewIssue(data.issue);
      break;
    // ... handle other message types
  }
};
```

### Message Types
1. Scan Progress Updates
2. New Issue Notifications
3. Configuration Changes
4. System Alerts

## Error Handling

### API Error Structure
```typescript
interface APIError {
  status_code: number;
  message: string;
  details?: Record<string, any>;
}

// Frontend error handling
try {
  const response = await api.get('/endpoint');
} catch (error) {
  if (error.response) {
    // Handle API errors
    handleAPIError(error.response.data);
  } else {
    // Handle network errors
    handleNetworkError(error);
  }
}
```

## Data Flow Examples

### 1. Initiating a Scan
```typescript
// Frontend
const startScan = async (config: ScanConfig) => {
  // 1. Send scan request
  const scan = await api.post('/api/scan/start', config);
  
  // 2. Connect to WebSocket for updates
  connectToScanWebSocket(scan.id);
  
  // 3. Poll for completion
  pollScanStatus(scan.id);
};
```

### 2. Fetching Dashboard Data
```typescript
// Frontend using React Query
const useDashboardData = () => {
  return useQuery('dashboard', async () => {
    const [metrics, trends] = await Promise.all([
      api.get('/api/dashboard/metrics'),
      api.get('/api/dashboard/trends')
    ]);
    return { metrics, trends };
  });
};
```

## Development Setup

### Environment Configuration
```bash
# Backend (.env)
DATABASE_URL=postgresql://user:pass@localhost:5432/db
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
JWT_SECRET=your_jwt_secret

# Frontend (.env.local)
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000
```

### Local Development
1. Start backend server:
   ```bash
   cd backend
   uvicorn main:app --reload
   ```

2. Start frontend development server:
   ```bash
   cd frontend
   npm run dev
   ```

## Testing Integration

### API Tests
- Implement integration tests using Jest
- Test all API endpoints
- Verify WebSocket connections
- Test error handling

### End-to-End Tests
- Use Cypress for E2E testing
- Test critical user flows
- Verify real-time updates
- Test error scenarios

## Deployment Considerations

### Backend Deployment
- Deploy FastAPI application using Docker
- Configure CORS settings
- Set up SSL certificates
- Configure WebSocket proxy

### Frontend Deployment
- Build and deploy Next.js application
- Configure environment variables
- Set up API proxy rules
- Enable SSL/TLS
