# Cloud Service Misconfiguration Scanner

A comprehensive AWS cloud configuration monitoring tool that identifies security misconfigurations, assesses risks, and provides actionable remediation steps through an intuitive visual interface.

## Project Structure

```
jazee/
├── backend/                # FastAPI backend
│   ├── src/               # Source code
│   │   ├── database/      # Database models and operations
│   │   ├── services/      # Business logic and AWS integration
│   │   ├── api/           # API endpoints
│   │   └── utils/         # Utility functions
│   ├── tests/             # Test suite
│   └── requirements.txt   # Python dependencies
└── frontend/              # Next.js frontend
    ├── app/              # Next.js 14 app directory
    │   ├── components/   # Reusable UI components
    │   └── page.tsx      # Main dashboard page
    ├── components/       # Shared components
    ├── lib/             # Utilities and hooks
    └── styles/          # Global styles
```

## Features

### Real-time Monitoring
- Live AWS service scanning (EC2, S3, IAM, RDS)
- WebSocket-based real-time updates
- Continuous security group and ACL monitoring
- Instant notification system for critical issues

### Visual Analytics
- Interactive security dashboard
- Risk severity classification with visual indicators
- Time-series trend analysis
- Resource relationship visualization
- Customizable data filtering and sorting

### Compliance Management
- CIS and PCI compliance monitoring
- Automated compliance scoring
- Historical compliance tracking
- Detailed violation reporting

### Reporting System
- Comprehensive PDF/CSV exports
- Customizable report templates
- Historical data analysis
- Automated report scheduling

## Technical Implementation

### Backend Architecture
- **Framework**: FastAPI for high-performance async operations
- **AWS Integration**: boto3 with custom wrapper for optimized calls
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Authentication**: JWT-based with refresh token mechanism
- **WebSocket**: FastAPI WebSocket support for real-time updates
- **Testing**: pytest with 80%+ coverage

### Frontend Architecture
- **Framework**: Next.js 14 with App Router
- **State Management**: Custom store with React Context
- **UI Components**: shadcn/ui with Radix UI primitives
- **Data Visualization**: Custom charts using D3.js
- **Real-time Updates**: WebSocket integration with reconnection logic
- **Type Safety**: Full TypeScript implementation

## Implementation Methods

### Frontend Components

#### Core UI Components
- **Theme Provider** (`theme-provider.tsx`)
  - Implements dark/light theme switching
  - Provides theme context to all components
  - Uses next-themes for persistence

#### Data Visualization
- **Chart Component** (`components/ui/chart.tsx`)
  - Real-time data visualization
  - Supports line, bar, and area charts
  - Implements D3.js for custom visualizations
  - WebSocket integration for live updates

#### Security Dashboard
- **Sidebar Navigation** (`components/ui/sidebar.tsx`)
  - Resource category filtering
  - Real-time status indicators
  - Service health monitoring

#### Interactive Elements
- **Data Tables** (`components/ui/table.tsx`)
  - Sortable and filterable columns
  - Pagination support
  - Real-time data updates
  - Export functionality

#### Form Components
- **Form Controls** (`components/ui/form.tsx`)
  - Form validation
  - Error handling
  - Dynamic field generation
  - Auto-save functionality

#### Notification System
- **Toast Notifications** (`components/ui/toast.tsx`)
  - Real-time alerts
  - Priority-based display
  - Customizable duration
  - Action buttons support

#### Modal Dialogs
- **Alert Dialog** (`components/ui/alert-dialog.tsx`)
  - Critical action confirmations
  - Error displays
  - Success notifications

### Backend Implementation

#### API Routes
1. **Main Routes** (`/src/api/routes.py`)
   ```python
   # Core endpoints for AWS service scanning
   GET /api/scan/start - Start new scan
   POST /api/scan/configure - Update scan settings
   GET /api/scan/status - Get current scan status
   ```

2. **Report Routes** (`/src/api/report_routes.py`)
   ```python
   # Report generation endpoints
   GET /api/reports - List all reports
   POST /api/reports/generate - Generate new report
   GET /api/reports/{id}/download - Download report
   ```

3. **Trend Routes** (`/src/api/trend_routes.py`)
   ```python
   # Trend analysis endpoints
   GET /api/trends/security - Security trend data
   GET /api/trends/compliance - Compliance trend data
   GET /api/trends/resources - Resource usage trends
   ```

#### WebSocket Implementation (`/src/api/websocket.py`)
```python
# Real-time update channels
/ws/scan-updates - Scan progress updates
/ws/alerts - Real-time security alerts
/ws/metrics - Live metric updates
```

#### Services Layer

1. **AWS Scanner Service**
   ```python
   class AWSScanner:
       async def scan_service(self, service_name: str):
           # Scans specific AWS service
       
       async def analyze_configuration(self, config: dict):
           # Analyzes service configuration
   ```

2. **Compliance Service**
   ```python
   class ComplianceChecker:
       def check_compliance(self, resource: dict):
           # Checks resource against compliance rules
       
       def generate_compliance_report(self):
           # Generates compliance report
   ```

3. **Report Generation Service**
   ```python
   class ReportGenerator:
       async def create_report(self, report_type: str):
           # Generates specified report type
       
       async def export_report(self, format: str):
           # Exports report in specified format
   ```

#### Database Models

1. **Resource Model**
   ```python
   class Resource(Base):
       id: str
       type: str
       configuration: JSON
       compliance_status: str
       last_checked: datetime
   ```

2. **Scan Model**
   ```python
   class Scan(Base):
       id: str
       status: str
       findings: JSON
       start_time: datetime
       end_time: datetime
   ```

### Integration Points

1. **Frontend to Backend Communication**
   ```typescript
   // Frontend API client
   class APIClient {
     async startScan(): Promise<ScanResult> {
       // Initiates new scan
     }
     
     async fetchReports(): Promise<Report[]> {
       // Fetches available reports
     }
   }
   ```

2. **WebSocket Connection**
   ```typescript
   // Frontend WebSocket handler
   class WebSocketManager {
     connect(): void {
       // Establishes WebSocket connection
     }
     
     handleUpdates(callback: (data: UpdateData) => void): void {
       // Handles incoming updates
     }
   }
   ```

3. **Data Flow**
   ```
   AWS Services -> Backend Scanner -> WebSocket -> Frontend Components
   User Action -> Frontend API Client -> Backend Endpoint -> Database
   ```

### Security Implementation

1. **Authentication**
   ```python
   # Backend JWT implementation
   class JWTHandler:
       def create_token(self, user_data: dict):
           # Creates JWT token
       
       def verify_token(self, token: str):
           # Verifies JWT token
   ```

2. **Authorization**
   ```python
   # Role-based access control
   class RBACHandler:
       def check_permission(self, user: User, resource: str):
           # Checks user permissions
   ```

### Error Handling

1. **Frontend Error Boundary**
   ```typescript
   class ErrorBoundary extends React.Component {
     handleError(error: Error): void {
       // Handles and logs errors
     }
   }
   ```

2. **Backend Error Handler**
   ```python
   class ErrorHandler:
       def handle_aws_error(self, error: Exception):
           # Handles AWS-specific errors
       
       def handle_database_error(self, error: Exception):
           # Handles database errors
   ```

## Getting Started

### Prerequisites

- Node.js 18+
- Python 3.9+
- PostgreSQL 13+
- AWS credentials configured

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configurations

# Run migrations
alembic upgrade head

# Start server
uvicorn src.main:app --reload
```

### Frontend Setup

```bash
cd frontend
npm install

# Set up environment variables
cp .env.example .env.local
# Edit .env.local with your configurations

# Development server
npm run dev

# Production build
npm run build
npm start
```

The application will be available at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

## Development

### Backend Development
- Follows REST API best practices
- Implements comprehensive error handling
- Includes request validation
- Features detailed logging system
- Supports async operations for improved performance

### Frontend Development
- Implements responsive design patterns
- Features accessibility considerations (WCAG 2.1)
- Supports dark/light theme
- Includes error boundary implementation
- Features progressive enhancement

### Code Quality
- ESLint and Prettier for code formatting
- Pre-commit hooks with husky
- Continuous Integration with GitHub Actions
- Automated testing on pull requests
- Type checking with mypy (backend) and TypeScript (frontend)

## Testing

```bash
# Backend tests
cd backend
pytest
pytest --cov=src tests/  # Coverage report

# Frontend tests
cd frontend
npm test
npm run test:e2e        # End-to-end tests
npm run test:coverage   # Coverage report
```

## Performance Metrics

- Dashboard initial load: < 3s
- API response time: < 2s
- WebSocket latency: < 100ms
- Scan completion time: < 5 minutes
- False positive rate: < 5%

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Write clean, documented code
- Follow the established code style
- Include tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting PR

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the development team.
