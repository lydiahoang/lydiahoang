import datetime
import time
import json
import pandas as pd
import boto3

from lydiahoang.logger_utils import get_logger

# Reference: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html

from pydash import retry

formatter, logger = get_logger(logger_name='lydiahoang')


class IamRolePolicyAudit:

    def __init__(self):
        self.client = boto3.client('iam')

    def list_all_roles(self) -> list:
        """Lists the IAM roles that have the specified path prefix.
        If none exists, the operation returns an empty list
        :return: lists all roles
        eg., in row[0]:
        {
            'all_roles': [
                        {
                        'Path': (1xxxxxxxxx)',
                        'RoleName': (1xxxxxxxxx4),
                        'RoleId': (3xxxxxxxxx5),
                        'Arn': (xxxxxxxxxx4),
                        'CreateDate': (2xxxxxxxxx),
                        'AssumeRolePolicyDocument': (xxxxxxxxxxx2),
                        'MaxSessionDuration': (xxxxxxxxxxx2),
                        },
                    ]
            IsTruncated': True|False,
            'Marker': 'string'
        }
        """

        marker = None
        all_roles = []
        paginator = self.client.get_paginator('list_roles')

        # 'PageSize' temporarily set
        response_iterator = paginator.paginate(
            PaginationConfig={'PageSize': 100, 'StartingToken': marker}
        )

        [all_roles.extend(page['Roles']) for page in response_iterator]

        logger.info(f"Total number of roles retrieved is:{len(all_roles)}")
        return all_roles


    def list_all_policies(self) -> list:
        """
        Lists all the managed policies that are available in the AWS account,
        including your own customer-defined managed policies and all AWS managed policies.
        :return: lists all policies
        """

        policy_arn_name = []
        marker = None
        paginator = self.client.get_paginator('list_policies')

        # 'PageSize' temporarily set
        response_iterator = paginator.paginate(
            PaginationConfig={'PageSize': 100, 'StartingToken': marker}
        )

        [policy_arn_name.extend(page['Policies']) for page in response_iterator]

        logger.info(f"Total number of policies retrieved is:{len(policy_arn_name)}")
        return policy_arn_name


    def get_job_id(self, arn: str) -> dict:
        """
        The ARN of the IAM resource (user, group, role, or managed policy)
        used to generate information about when the resource was last used
        in an attempt to access an AWS service.
        :return: the Job Id by using the Arn
        """

        response = self.client.generate_service_last_accessed_details(
            Arn=arn
        )
        return response['JobId']


    @retry(attempts=4,
           delay=20,
           max_delay=150.0,
           scale=2.0,
           jitter=0,
           exceptions=(TimeoutError,))
    def get_job_result(self, job_id: str) -> dict:
        """
        After a user, group, role, or policy report is generated using the GenerateServiceLastAccessedDetails
        operation, use the JobId parameter in GetServiceLastAccessedDetails .
        This operation retrieves the status of the report job and a list of AWS
        services that the resource (user, group, role, or managed policy) can access.
        :return: the last accessed details by using the Job Id
        """

        response = self.client.get_service_last_accessed_details(
            JobId=job_id
        )

        if response['JobStatus'] == 'IN_PROGRESS':
            time.sleep(5)
            logger.info(f"Getting service_last_accessed_details is in progress for: {job_id}")
        elif response['JobStatus'] == 'FAILED':
            logger.info(f"Timeouterror occurred at: {job_id}")
            raise TimeoutError

        return response


    def list_policies_attached_to_a_role(self, role_name) -> dict:
        """
        Lists all managed policies that are attached to the specified IAM role.
        An IAM role can also have inline policies embedded with it.
        To list the inline policies for a role, use the ListRolePolicies API.
        :return: list of managed policies attached to a specified role
        """
        response = None
        marker = None

        # By default, only 100 items are returned at a time.
        # 'Marker' is used for pagination.
        while response is None or response['IsTruncated']:
            if marker is None:
                response = self.client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            else:
                response = self.client.list_attached_role_policies(RoleName=role_name,Marker=marker)['AttachedPolicies']

            if response['IsTruncated']:
                marker = response['Marker']

        logger.info(f"All managed policies attached to an IAM role has completed")
        return response


    def list_roles_attached_to_a_policy(self, policy_arn) -> dict:
        """
        Lists all IAM users, groups, and roles that the specified managed policy is attached to.
        :return: list of roles and managed policies attached
        """
        response = None
        marker = None

        # By default, only 100 items are returned at a time.
        # 'Marker' is used for pagination.
        while response is None or response['IsTruncated']:
            if marker is None:
                response = self.client.list_entities_for_policy(RoleName=policy_arn)['PolicyRoles']
            else:
                response = self.client.list_entities_for_policy(RoleName=policy_arn,Marker=marker)['PolicyRoles']

            if response['IsTruncated']:
                marker = response['Marker']
        logger.info(f"List of roles have been attached to the managed policies")
        return response


    def get_policy_document(self, policy) -> list:
        """
        Retrieves information about the specified version of the specified managed policy,
        including the policy document.
        :param policy eg: {
                            'Arn': 'arn:aws:iam::aws:policy/Amazonxxxxxxxxxxxxxxxxx_FullAccess',
                            'PolicyName': 'Amazonxxxxxxxxxxxxxxxxx_FullAccess',
                            'DefaultVersionId': 'version1'
                            }
        :return: list of dicts with iam policy statements
        """
        policy_version = self.client.get_policy_version(
            PolicyArn=policy['Arn'],
            VersionId=policy['DefaultVersionId']
        )

        logger.info(f"The retrieval of policy versions has completed")
        return policy_version['PolicyVersion']['Document']['Statement']


    def generate_report(self, resources: list):
        """
        Combine the generated report for all resources in the list Roles | Policies
        :param resources: Roles | Policies
        :return: report with used roles and policies
        """
        all_resources = resources
        job_result_list = []
        logger.info(f"The report is in progress...")
        for resource in all_resources:
            job_id = self.get_job_id(resource['Arn'])
            job_result_list.append(self.get_job_result(job_id))

        logger.info(f"The report has been generated")
        return job_result_list


    def retrieve_all_job_results_as_json(self, arn_list):
        def default(o):
            if isinstance(o, (datetime.date, datetime.datetime)):
                return o.isoformat()

        job_result_list = []
        job_result_total = {'result': job_result_list}
        for arn in arn_list:
            job_id = self.get_job_id(arn['Arn'])
            job_result_list.append(self.get_job_result(job_id))
        return json.dumps(job_result_total, default=default)


def role_assessment():
    audit = IamRolePolicyAudit()
    all_roles = audit.list_all_roles()
    roles_list = []
    role_used = []
    services_used_list = []
    services_unused_list = []
    services_accessable = []
    last_authenticated = []
    for role in all_roles:
        job_id = audit.get_job_id(role['Arn'])
        job_result = audit.get_job_result(job_id)
        job_last_accessed = audit.get_job_result(job_id)['ServicesLastAccessed']
        services_accessed = [job['TotalAuthenticatedEntities'] for job in job_last_accessed]
        roles_list.append(role['Arn'])
        services_used = len([x for x in services_accessed if x > 0])
        services_unused = len([x for x in services_accessed if x == 0])
        services_used_list.append(services_used)
        services_unused_list.append(services_unused)
        services_accessable.append(services_used + services_unused)
        role_used.append(True if services_used > 0 else False)

        services_last_accessed = [item['LastAuthenticated'] for item in job_last_accessed if
                          item['TotalAuthenticatedEntities'] > 0]
        latest = max(services_last_accessed, default=0)
        if latest is 0:
            index = latest
        last_authenticated.append(latest)

    return pd.DataFrame({'role_arn': roles_list,
                         'role_used': role_used,
                         'services_used_list': services_used_list,
                         'services_unused_list': services_unused_list,
                         'services_accessable': services_accessable,
                         'last_authenticated': last_authenticated})




if __name__ == "__main__":
    roles = role_assessment()
    used = roles['role_used'].value_counts()
    roles.to_csv('roles_audit')

