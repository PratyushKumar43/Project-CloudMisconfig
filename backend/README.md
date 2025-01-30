# Cloud Service Misconfiguration Scanner Backend

This is the backend service for the AWS Cloud Misconfiguration Scanner. It provides APIs for scanning and monitoring AWS service configurations for security issues and compliance.

## Features

- Real-time AWS service security scanning
- Vulnerability detection and reporting
- Compliance checking (PCI DSS, HIPAA, SOC 2)
- Service overview and metrics
- REST API endpoints for frontend integration

## Prerequisites

- Python 3.9+
- AWS CLI configured with appropriate permissions
- Virtual environment (recommended)

## Setup

1. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the development server:
```bash
cd src
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

## API Endpoints

- GET `/api/overview` - Get service overview
- GET `/api/vulnerabilities` - Get vulnerability report
- GET `/api/compliance` - Get compliance status
- POST `/api/scan` - Trigger new security scan

## Testing

Run tests using pytest:
```bash
pytest
```

## AWS Permissions Required

The AWS credentials should have permissions for:
- EC2 (DescribeInstances, DescribeSecurityGroups)
- S3 (ListBuckets, GetBucketPolicy)
- RDS (DescribeDBInstances)
- CloudWatch (GetMetricData)
