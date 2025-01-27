1. AWS Infrastructure Setup
IAM Role Creation
jsonCopy// IAMAnalyzerRole Trust Policy
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

// IAMAnalyzerRole Permissions Policy
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:ListRoles",
                "iam:ListUsers",
                "iam:GetServiceLastAccessedDetails",
                "s3:PutObject",
                "s3:GetObject",
                "sts:AssumeRole"
            ],
            "Resource": [
                "arn:aws:iam::*:role/IAMAnalyzerRole",
                "arn:aws:s3:::iam-analyze-report/*"
            ]
        }
    ]
}
S3 Bucket Setup

Create bucket: iam-analyze-report
Enable versioning
Apply encryption

EC2 Instance

Launch Amazon Linux 2 instance
Instance type: t3.medium minimum
Storage: 20GB gp3
Security group: Allow SSH access

2. Environment Setup
bashCopy# System updates
sudo yum update -y
sudo yum install python3 python3-pip git -y

# Create directories
mkdir -p /opt/iam-analyzer/{output,logs,config}
sudo chown -R ec2-user:ec2-user /opt/iam-analyzer

# Install Python packages
pip3 install boto3 pandas openpyxl

# Configure AWS credentials
aws configure
3. Configuration File
Create /opt/iam-analyzer/config/accounts_config.json:
jsonCopy{
    "cross_account_role": "IAMAnalyzerRole",
    "analysis_period_days": 90,
    "output_path": "/opt/iam-analyzer/output",
    "s3_bucket": "iam-analyze-report",
    "s3_prefix": "iam-analysis",
    "accounts": [
        {
            "id": "ACCOUNT_ID",
            "name": "AccountName",
            "environment": "prod"
        }
    ]
}
4. Script Deployment

Copy the Python script to /opt/iam-analyzer/iam_analyzer.py
Set permissions: chmod +x /opt/iam-analyzer/iam_analyzer.py

5. Required Permissions Matrix
ResourcePermissionPurposeEC2AmazonEC2FullAccessRun analyzer instanceIAMCustom policyAccess IAM resourcesS3S3 bucket accessStore reports
6. Testing
bashCopy# Test AWS credentials
aws sts get-caller-identity

# Test script
python3 /opt/iam-analyzer/iam_analyzer.py
7. Maintenance
Monitoring

Set up CloudWatch alarms for EC2 metrics
Monitor S3 bucket usage
Check IAM analyzer logs

Updates

Regular yum updates
Python package updates
Script version control

8. Security Considerations

Use VPC endpoints
Implement least privilege access
Enable CloudTrail logging
Regular security patches
Encrypt sensitive data

9. Troubleshooting
Common issues and solutions:

Permission denied: Check IAM roles
S3 access failed: Verify bucket permissions
Script errors: Check logs in /opt/iam-analyzer/logs

10. Support
Create internal documentation for:

Contact points
Escalation procedures
Regular maintenance schedule
Backup procedures