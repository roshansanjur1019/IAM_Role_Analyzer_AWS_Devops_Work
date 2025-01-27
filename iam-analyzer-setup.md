# IAM Permissions Analyzer Setup Guide

## Overview
This guide details the setup required to analyze IAM permissions across multiple AWS accounts using the IAM Permissions Analyzer script.

## Source Account Setup (Where Script Runs)

### 1. Script Location
- Place `iam-permission-analyzer.py` in `/opt/iam-analyzer/`
- Ensure proper execution permissions: `chmod +x /opt/iam-analyzer/iam-permission-analyzer.py`

### 2. Configuration File
Create `/opt/iam-analyzer/config/accounts_config.json`:
```json
{
    "cross_account_role": "IAMAnalyzerRole",
    "output_path": "/opt/iam-analyzer/output",
    "s3_bucket": "your-s3-bucket-name",
    "s3_prefix": "iam-analysis",
    "analysis_period_days": 90,
    "accounts": [
        {
            "id": "TARGET-ACCOUNT-ID",
            "name": "Account-Name",
            "environment": "prod"
        }
    ]
}
```

## Target Account Setup (Accounts to be Analyzed)

### 1. Create IAM Role
Create a role named "IAMAnalyzerRole" with the following configurations:

#### Trust Relationship
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::SOURCE-ACCOUNT-ID:root"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

#### Permissions Policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListGroups",
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListAttachedGroupPolicies",
                "iam:ListGroupPolicies",
                "iam:GenerateServiceLastAccessedDetails",
                "iam:GetServiceLastAccessedDetails",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:GetRole",
                "iam:ListRoles",
                "iam:ListGroupsForUser",
                "iam:ListAttachedUserPolicies",
                "iam:ListUserPolicies",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:GetUser",
                "iam:ListEntitiesForPolicy",
                "iam:GetGroup",
                "iam:GetRolePolicy",
                "iam:GetUserPolicy",
                "iam:GetGroupPolicy"
            ],
            "Resource": "*"
        }
    ]
}
```

## Execution Steps

1. Create required directories:
```bash
mkdir -p /opt/iam-analyzer/{logs,output,config}
```

2. Verify target account role:
```bash
aws sts assume-role --role-arn arn:aws:iam::TARGET-ACCOUNT-ID:role/IAMAnalyzerRole --role-session-name TestSession
```

3. Run the analyzer:
```bash
python /opt/iam-analyzer/iam-permission-analyzer.py
```

## Output Location
- Excel report: `/opt/iam-analyzer/output/`
- S3 bucket: `s3://your-s3-bucket-name/iam-analysis/`
- Logs: `/opt/iam-analyzer/logs/analyzer.log`

## Troubleshooting

Common issues and solutions:

1. Access Denied
- Verify trust relationship in target account
- Check permissions policy attached to IAMAnalyzerRole
- Ensure source account has permission to assume role

2. Missing Data
- Check analyzer logs
- Verify all required IAM permissions are included
- Ensure role name matches config file

3. S3 Upload Fails
- Verify S3 bucket exists
- Check bucket permissions
- Ensure correct bucket name in config