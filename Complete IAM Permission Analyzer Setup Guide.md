# Complete IAM Permission Analyzer Setup and Implementation Guide

## 1. Infrastructure Setup

### IAM Roles & Policies

#### Source Account (Where EC2 runs)
1. Create EC2 Instance Role
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/IAMAnalyzerRole"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::iam-analyze-report/*"
        }
    ]
}
```

2. Create IAM User
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::TARGET_ACCOUNT_ID:role/IAMAnalyzerRole"
        }
    ]
}
```

#### Target Accounts (Accounts to Analyze)
1. Create IAMAnalyzerRole
```json
// Trust Policy
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:user/iam-analyzer-user"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

// Permissions Policy
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
                "iam:ListGroups",
                "iam:ListGroupPolicies",
                "iam:ListAttachedGroupPolicies",
                "iam:ListPolicies",
                "iam:GetGroupPolicy"
            ],
            "Resource": "*"
        }
    ]
}
```

### S3 Bucket Setup
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:role/EC2-IAM-Analyzer-Role"
            },
            "Action": [
                "s3:PutObject",
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::iam-analyze-report/*"
        }
    ]
}
```

## 2. EC2 Setup

```bash
# Update system
sudo yum update -y
sudo yum install python3 python3-pip git -y

# Create directories
mkdir -p /opt/iam-analyzer/{output,logs,config}
sudo chown -R ec2-user:ec2-user /opt/iam-analyzer

# Install Python packages
pip3 install boto3 pandas openpyxl
```

## 3. Configuration

```json
{
    "cross_account_role": "IAMAnalyzerRole",
    "analysis_period_days": 90,
    "output_path": "/opt/iam-analyzer/output",
    "s3_bucket": "iam-analyze-report",
    "s3_prefix": "iam-analysis",
    "accounts": [
        {
            "id": "111111111111",
            "name": "Production",
            "environment": "prod"
        }
    ]
}
```

## 4. Complete Python Script

```python
[Previous complete script with added group and policy analysis]
```

## 5. Implementation Steps

1. **Source Account Setup**
   - Create S3 bucket
   - Create EC2 role
   - Launch EC2 instance
   - Configure AWS credentials

2. **Target Account Setup** (Repeat for each account)
   - Create IAMAnalyzerRole
   - Update trust relationships
   - Apply permissions policy
   - Enable IAM Access Analyzer
   - Enable CloudTrail

3. **Script Deployment**
```bash
# Copy script
vim /opt/iam-analyzer/iam_analyzer.py
# Paste complete script
chmod +x /opt/iam-analyzer/iam_analyzer.py

# Create config
vim /opt/iam-analyzer/config/accounts_config.json
# Paste configuration
```

4. **Testing**
```bash
# Test AWS credentials
aws sts get-caller-identity

# Test cross-account access
aws sts assume-role --role-arn arn:aws:iam::TARGET_ACCOUNT_ID:role/IAMAnalyzerRole --role-session-name test

# Run script
python3 /opt/iam-analyzer/iam_analyzer.py
```

## 6. Excel Report Structure

1. Executive Summary
   - Account overview
   - Risk levels
   - Resource counts

2. Detailed Analysis
   - Unused permissions
   - Last access dates
   - Risk assessment

3. Policies
   - Policy details
   - Usage information
   - Attached entities

4. Groups
   - Group memberships
   - Attached policies
   - Usage patterns

5. Recommendations
   - Action items
   - Risk mitigation
   - Timeline

## 7. Maintenance

1. Regular Tasks
   - Update account list
   - Review permissions
   - Check logs

2. Monitoring
   - CloudWatch alarms
   - S3 usage
   - Script execution

3. Updates
   - Security patches
   - Dependency updates
   - Policy reviews

## 8. Troubleshooting

1. Permission Issues
   - Verify role trust
   - Check policy attachments
   - Validate ARNs

2. Script Errors
   - Check logs
   - Verify AWS credentials
   - Confirm S3 access

3. Report Generation
   - Disk space
   - Memory usage
   - Excel formatting