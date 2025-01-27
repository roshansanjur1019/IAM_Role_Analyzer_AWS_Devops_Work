import boto3
import pandas as pd
from datetime import datetime, timezone
import json
import os
import logging
from logging.handlers import RotatingFileHandler
from botocore.exceptions import ClientError
import threading
from queue import Queue
import openpyxl

# Set up logging
log_file = '/opt/iam-analyzer/logs/analyzer.log'
os.makedirs(os.path.dirname(log_file), exist_ok=True)
handler = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=5)
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more detailed logging
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[handler, logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class IAMAnalyzer:
    def __init__(self, config_path):
        self.accounts_data = Queue()
        self.lock = threading.Lock()
        self.config = self.load_config(config_path)
        self.output_path = self.config['output_path']
        self.s3_client = boto3.client('s3')

    def convert_to_naive_datetime(self, dt):
        if isinstance(dt, datetime):
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
        
    def load_config(self, config_path):
        try:
            if not os.path.exists(config_path):
                raise FileNotFoundError(f"Config file not found at {config_path}")

            with open(config_path, 'r') as f:
                config = json.load(f)

            required_fields = ['cross_account_role', 'output_path', 's3_bucket', 's3_prefix', 'accounts']
            missing_fields = [field for field in required_fields if field not in config]
            if missing_fields:
                raise ValueError(f"Missing required fields in config: {', '.join(missing_fields)}")

            if not isinstance(config['accounts'], list):
                raise ValueError("'accounts' must be a list")
            
            if not config['accounts']:
                raise ValueError("No accounts specified in config")

            for i, account in enumerate(config['accounts']):
                required_account_fields = ['id', 'name', 'environment']
                missing_account_fields = [field for field in required_account_fields if field not in account]
                if missing_account_fields:
                    raise ValueError(f"Account at index {i} missing required fields: {', '.join(missing_account_fields)}")

            logger.info(f"Loaded configuration with {len(config['accounts'])} accounts")
            return config

        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            raise

    def assume_role(self, account_id, role_name):
        try:
            sts_client = boto3.client('sts')
            role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
            logger.info(f"Attempting to assume role: {role_arn}")
            
            assumed_role = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f'IAMAnalysis-{account_id}'
            )
            
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            )
            
            return iam_client
        except Exception as e:
            logger.error(f"Error assuming role in account {account_id}: {str(e)}")
            return None

    def get_service_last_accessed_details(self, iam_client, arn):
        try:
            logger.info(f"Generating service last accessed details for: {arn}")
            response = iam_client.generate_service_last_accessed_details(Arn=arn)
            job_id = response['JobId']
            max_attempts = 30
            attempt = 0
            
            while attempt < max_attempts:
                response = iam_client.get_service_last_accessed_details(JobId=job_id)
                if response['JobStatus'] == 'COMPLETED':
                    return response['ServicesLastAccessed']
                elif response['JobStatus'] == 'FAILED':
                    logger.error(f"Job failed for ARN: {arn}")
                    return []
                attempt += 1
                threading.Event().wait(2)
            
            logger.warning(f"Timeout waiting for job completion for ARN: {arn}")
            return []
        except Exception as e:
            logger.error(f"Error getting last accessed details for {arn}: {str(e)}")
            return []

    def get_policy_details(self, iam_client, policy_arn):
        try:
            logger.info(f"Retrieving policy details for: {policy_arn}")
            policy = iam_client.get_policy(PolicyArn=policy_arn)
            version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy['Policy']['DefaultVersionId']
            )
            return policy['Policy'], version['PolicyVersion']['Document']
        except Exception as e:
            logger.error(f"Error getting policy details for {policy_arn}: {str(e)}")
            return None, None

    def analyze_account(self, account_info):
        account_id = account_info['id']
        logger.info(f"Starting analysis for account {account_id}")
        
        try:
            iam_client = self.assume_role(account_id, self.config['cross_account_role'])
            if not iam_client:
                logger.error(f"Failed to assume role in account {account_id}")
                return
            
            account_data = {
                'account_id': account_id,
                'account_name': account_info.get('name', 'Unknown'),
                'environment': account_info.get('environment', 'Unknown'),
                'roles': [],
                'users': [],
                'groups': [],
                'policies': []
            }

            # Analyze Roles
            logger.info(f"Analyzing roles for account {account_id}")
            paginator = iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    if role['Path'].startswith('/aws-service-role/'):
                        continue
                    
                    try:
                        role_name = role['RoleName']
                        role_arn = role['Arn']
                        
                        # Get attached policies
                        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                        inline_policies = iam_client.list_role_policies(RoleName=role_name)
                        
                        # Get last accessed information
                        last_accessed = self.get_service_last_accessed_details(iam_client, role_arn)
                        
                        role_data = {
                            'ResourceType': 'Role',
                            'ResourceName': role_name,
                            'CreateDate': role['CreateDate'].strftime('%Y-%m-%d'),
                            'Path': role['Path'],
                            'Arn': role_arn,
                            'AttachedPolicies': [p['PolicyName'] for p in attached_policies['AttachedPolicies']],
                            'InlinePolicies': inline_policies['PolicyNames'],
                            'Description': role.get('Description', ''),
                            'LastAccessed': last_accessed
                        }
                        account_data['roles'].append(role_data)
                        
                    except Exception as e:
                        logger.error(f"Error analyzing role {role_name}: {str(e)}")

            # Analyze Users
            logger.info(f"Analyzing users for account {account_id}")
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    try:
                        user_name = user['UserName']
                        user_arn = user['Arn']
                        
                        # Get user details
                        groups = iam_client.list_groups_for_user(UserName=user_name)
                        attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
                        inline_policies = iam_client.list_user_policies(UserName=user_name)
                        
                        # Get access keys
                        access_keys = iam_client.list_access_keys(UserName=user_name)
                        access_key_details = []
                        for key in access_keys['AccessKeyMetadata']:
                            key_last_used = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                            access_key_details.append({
                                'AccessKeyId': key['AccessKeyId'],
                                'Status': key['Status'],
                                'CreateDate': key['CreateDate'].strftime('%Y-%m-%d'),
                                'LastUsed': key_last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate', 'Never')
                            })
                        
                        last_accessed = self.get_service_last_accessed_details(iam_client, user_arn)
                        
                        user_data = {
                            'ResourceType': 'User',
                            'ResourceName': user_name,
                            'CreateDate': user['CreateDate'].strftime('%Y-%m-%d'),
                            'Arn': user_arn,
                            'Path': user['Path'],
                            'Groups': [g['GroupName'] for g in groups['Groups']],
                            'AttachedPolicies': [p['PolicyName'] for p in attached_policies['AttachedPolicies']],
                            'InlinePolicies': inline_policies['PolicyNames'],
                            'AccessKeys': access_key_details,
                            'PasswordLastUsed': user.get('PasswordLastUsed', 'Never'),
                            'LastAccessed': last_accessed
                        }
                        account_data['users'].append(user_data)
                        
                    except Exception as e:
                        logger.error(f"Error analyzing user {user_name}: {str(e)}")

            # Analyze Groups
            logger.info(f"Analyzing groups for account {account_id}")
            paginator = iam_client.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page['Groups']:
                    try:
                        group_name = group['GroupName']
                        group_arn = group['Arn']
                        
                        # Get group details
                        group_users = iam_client.get_group(GroupName=group_name)
                        attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)
                        inline_policies = iam_client.list_group_policies(GroupName=group_name)
                        
                        last_accessed = self.get_service_last_accessed_details(iam_client, group_arn)
                        
                        group_data = {
                            'ResourceType': 'Group',
                            'ResourceName': group_name,
                            'CreateDate': group['CreateDate'].strftime('%Y-%m-%d'),
                            'Arn': group_arn,
                            'Path': group['Path'],
                            'Members': [u['UserName'] for u in group_users['Users']],
                            'MemberCount': len(group_users['Users']),
                            'AttachedPolicies': [p['PolicyName'] for p in attached_policies['AttachedPolicies']],
                            'InlinePolicies': inline_policies['PolicyNames'],
                            'LastAccessed': last_accessed
                        }
                        account_data['groups'].append(group_data)
                        
                    except Exception as e:
                        logger.error(f"Error analyzing group {group_name}: {str(e)}")

            # Analyze Policies
            logger.info(f"Analyzing policies for account {account_id}")
            paginator = iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    try:
                        policy_arn = policy['Arn']
                        
                        # Get policy details and document
                        policy_details, policy_doc = self.get_policy_details(iam_client, policy_arn)
                        if not policy_details:
                            continue
                        
                        # Get attached entities
                        entities_paginator = iam_client.get_paginator('list_entities_for_policy')
                        attached_users = []
                        attached_roles = []
                        attached_groups = []
                        
                        for entities_page in entities_paginator.paginate(PolicyArn=policy_arn):
                            attached_users.extend([u['UserName'] for u in entities_page.get('PolicyUsers', [])])
                            attached_roles.extend([r['RoleName'] for r in entities_page.get('PolicyRoles', [])])
                            attached_groups.extend([g['GroupName'] for g in entities_page.get('PolicyGroups', [])])
                        
                        policy_data = {
                            'PolicyName': policy['PolicyName'],
                            'PolicyId': policy['PolicyId'],
                            'CreateDate': policy['CreateDate'].strftime('%Y-%m-%d'),
                            'UpdateDate': policy['UpdateDate'].strftime('%Y-%m-%d'),
                            'Path': policy['Path'],
                            'Arn': policy_arn,
                            'AttachmentCount': policy['AttachmentCount'],
                            'AttachedUsers': attached_users,
                            'AttachedRoles': attached_roles,
                            'AttachedGroups': attached_groups,
                            'PolicyDocument': policy_doc
                        }
                        account_data['policies'].append(policy_data)
                        
                    except Exception as e:
                        logger.error(f"Error analyzing policy {policy['PolicyName']}: {str(e)}")

            self.accounts_data.put(account_data)
            logger.info(f"Completed analysis for account {account_id}")
            
        except Exception as e:
            logger.error(f"Error analyzing account {account_id}: {str(e)}")
            raise

    def analyze_accounts(self):
        logger.info("Starting parallel account analysis")
        threads = []
        for account in self.config['accounts']:
            thread = threading.Thread(target=self.analyze_account, args=(account,))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        return self.compile_results()

    def compile_results(self):
        results = []
        while not self.accounts_data.empty():
            results.append(self.accounts_data.get())
        logger.info(f"Compiled results for {len(results)} accounts")
        return results

    def save_to_excel(self, results, filename):
        filepath = os.path.join(self.output_path, filename)
        os.makedirs(self.output_path, exist_ok=True)
        
        logger.info(f"Saving results to Excel file: {filepath}")
        with pd.ExcelWriter(filepath, engine='openpyxl', datetime_format='YYYY-MM-DD') as writer:
            # Resources Overview sheet
            resources_data = []
            for account in results:
                resources_data.append({
                    'Account ID': account['account_id'],
                    'Account Name': account['account_name'],
                    'Environment': account['environment'],
                    'Users Count': len(account['users']),
                    'Roles Count': len(account['roles']),
                    'Groups Count': len(account['groups']),
                    'Local Policies Count': len(account['policies'])
                })
            
            df_resources = pd.DataFrame(resources_data)
            df_resources.to_excel(writer, sheet_name='Resources Overview', index=False)

            # Roles sheet
            roles_data = []
            for account in results:
                for role in account['roles']:
                    role_data = {
                        'Account ID': account['account_id'],
                        'Account Name': account['account_name'],
                        'Environment': account['environment'],
                        'Role Name': role['ResourceName'],
                        'ARN': role['Arn'],
                        'Create Date': role['CreateDate'],
                        'Path': role['Path'],
                        'Description': role.get('Description', ''),
                        'Attached Policies': ', '.join(role['AttachedPolicies']),
                        'Inline Policies': ', '.join(role['InlinePolicies'])
                    }
                    
                    # Add last accessed details with timezone handling
                    last_accessed = role.get('LastAccessed', [])
                    if last_accessed:
                        services_used = []
                        for svc in last_accessed:
                            last_auth = svc.get('LastAuthenticated')
                            if isinstance(last_auth, datetime):
                                services_used.append(self.convert_to_naive_datetime(last_auth))
                        if services_used:
                            latest_use = max(services_used)
                            role_data['Last Used'] = latest_use
                        else:
                            role_data['Last Used'] = 'Never'
                    else:
                        role_data['Last Used'] = 'Never'
                    
                    roles_data.append(role_data)
            
            if roles_data:
                df_roles = pd.DataFrame(roles_data)
                df_roles.to_excel(writer, sheet_name='Roles', index=False)

            # Users sheet
            users_data = []
            for account in results:
                for user in account['users']:
                    user_data = {
                        'Account ID': account['account_id'],
                        'Account Name': account['account_name'],
                        'Environment': account['environment'],
                        'User Name': user['ResourceName'],
                        'ARN': user['Arn'],
                        'Create Date': user['CreateDate'],
                        'Path': user['Path'],
                        'Groups': ', '.join(user['Groups']),
                        'Attached Policies': ', '.join(user['AttachedPolicies']),
                        'Inline Policies': ', '.join(user['InlinePolicies']),
                        'Password Last Used': user['PasswordLastUsed']
                    }
                    
                    # Add access key details with timezone handling
                    access_keys = user.get('AccessKeys', [])
                    if access_keys:
                        user_data['Access Keys'] = len(access_keys)
                        for idx, key in enumerate(access_keys, 1):
                            user_data[f'Access Key {idx} ID'] = key['AccessKeyId']
                            user_data[f'Access Key {idx} Status'] = key['Status']
                            user_data[f'Access Key {idx} Create Date'] = key['CreateDate']
                            last_used = key.get('LastUsed')
                            if isinstance(last_used, datetime):
                                user_data[f'Access Key {idx} Last Used'] = self.convert_to_naive_datetime(last_used)
                            else:
                                user_data[f'Access Key {idx} Last Used'] = last_used
                    
                    users_data.append(user_data)
            
            if users_data:
                df_users = pd.DataFrame(users_data)
                df_users.to_excel(writer, sheet_name='Users', index=False)

            # Groups sheet
            groups_data = []
            for account in results:
                for group in account['groups']:
                    groups_data.append({
                        'Account ID': account['account_id'],
                        'Account Name': account['account_name'],
                        'Environment': account['environment'],
                        'Group Name': group['ResourceName'],
                        'ARN': group['Arn'],
                        'Create Date': group['CreateDate'],
                        'Path': group['Path'],
                        'Member Count': group['MemberCount'],
                        'Members': ', '.join(group['Members']),
                        'Attached Policies': ', '.join(group['AttachedPolicies']),
                        'Inline Policies': ', '.join(group['InlinePolicies'])
                    })
            
            if groups_data:
                df_groups = pd.DataFrame(groups_data)
                df_groups.to_excel(writer, sheet_name='Groups', index=False)

            # Policies sheet
            policies_data = []
            for account in results:
                for policy in account['policies']:
                    policies_data.append({
                        'Account ID': account['account_id'],
                        'Account Name': account['account_name'],
                        'Environment': account['environment'],
                        'Policy Name': policy['PolicyName'],
                        'Policy ID': policy['PolicyId'],
                        'ARN': policy['Arn'],
                        'Create Date': policy['CreateDate'],
                        'Update Date': policy['UpdateDate'],
                        'Path': policy['Path'],
                        'Attachment Count': policy['AttachmentCount'],
                        'Attached Users': ', '.join(policy['AttachedUsers']),
                        'Attached Roles': ', '.join(policy['AttachedRoles']),
                        'Attached Groups': ', '.join(policy['AttachedGroups']),
                        'Policy Document': json.dumps(policy['PolicyDocument'], indent=2)
                    })
            
            if policies_data:
                df_policies = pd.DataFrame(policies_data)
                df_policies.to_excel(writer, sheet_name='Policies', index=False)

            # Format all sheets
            workbook = writer.book
            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                
                # Header formatting
                header_fill = openpyxl.styles.PatternFill(start_color='366092', end_color='366092', fill_type='solid')
                header_font = openpyxl.styles.Font(color='FFFFFF', bold=True)
                
                for cell in worksheet[1]:
                    cell.fill = header_fill
                    cell.font = header_font
                
                # Auto-adjust column widths
                for column in worksheet.columns:
                    max_length = 0
                    column = [cell for cell in column]
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column[0].column_letter].width = adjusted_width

        logger.info(f"Results saved to {filepath}")
        return filepath

    def upload_to_s3(self, local_file):
        try:
            filename = os.path.basename(local_file)
            current_date = datetime.now()
            
            account_env = self.config['accounts'][0].get('environment', 'unknown') if self.config['accounts'] else 'unknown'
            
            s3_key = (
                f"{self.config['s3_prefix']}/"
                f"environment={account_env}/"
                f"year={current_date.year}/"
                f"month={current_date.strftime('%m')}/"
                f"day={current_date.strftime('%d')}/"
                f"{filename}"
            )
            
            logger.info(f"Uploading results to S3: s3://{self.config['s3_bucket']}/{s3_key}")
            self.s3_client.upload_file(local_file, self.config['s3_bucket'], s3_key)
            logger.info(f"Successfully uploaded results to s3://{self.config['s3_bucket']}/{s3_key}")
            
        except Exception as e:
            logger.error(f"Error uploading to S3: {str(e)}")
            raise

def main():
    try:
        config_path = '/opt/iam-analyzer/config/accounts_config.json'
        if not os.path.exists(config_path):
            logger.error(f"Config file not found at {config_path}")
            return
            
        analyzer = IAMAnalyzer(config_path)
        logger.info("Starting IAM permissions analysis...")
        
        results = analyzer.analyze_accounts()
        if not results:
            logger.error("No results generated from analysis!")
            return
        
        environment = analyzer.config['accounts'][0].get('environment', 'unknown') if analyzer.config['accounts'] else 'unknown'
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output_file = f"iam_permissions_analysis_{environment}_{timestamp}.xlsx"
        
        local_path = analyzer.save_to_excel(results, output_file)
        analyzer.upload_to_s3(local_path)
        
        logger.info("Analysis complete")
        
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")
        raise

if __name__ == "__main__":
    main()
