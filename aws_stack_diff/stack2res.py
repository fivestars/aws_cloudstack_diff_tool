#!/usr/bin/env python3
from __future__ import unicode_literals, print_function, absolute_import

from aws_stack_diff.utils import walk_json, json_default, sorted_dict, base64_decode


def stack2res(boto_session, stack_name):
    """from a stack name, transform into a dict of resources"""
    return Stack2Res(boto_session, stack_name).get_processed()


class Stack2Res(object):
    def __init__(self, boto_session, stack_name):
        self._bs = boto_session
        self._stack_name = stack_name

        self._stack_info = self._bs.cf.describe_stacks(StackName=stack_name)[0]
        self._template = self._bs.cf.get_template(StackName=stack_name)
        self._resources = self._bs.cf.describe_stack_resources(StackName=stack_name)

        self._user = self._bs.iam.get_user()

        self.ref_values = {
            'AWS::AccountId': self._user['Arn'].split(':')[4],
            # 'AWS::NotificationARNs': '',
            # 'AWS::NoValue': '',
            'AWS::Region': self._bs._session.region_name,
            'AWS::StackId': self._stack_info['StackId'],
            'AWS::StackName': self._stack_info['StackName'],
        }
        self.ref_values.update({r['LogicalResourceId']: r.get('PhysicalResourceId') for r in self._resources})

    def get_tags(self, log_id):
        # TODO use that, instead of filtering thoses names in resources
        return {
            'aws:cloudformation:logical-id': log_id,
            'aws:cloudformation:stack-id': self._stack_info['StackId'],
            'aws: cloudformation:stack-name': self._stack_name,
        }

    def walk_dict(self, d):
        if 'Ref' in d:
            assert {'Ref'} == set(d.keys())
            return self.ref_values.get(d['Ref'])
        if 'Fn::Join' in d:
            assert {'Fn::Join'} == set(d.keys())
            sep, values = d['Fn::Join']
            return sep.join(values)
        if 'Fn::GetAtt' in d:
            assert {'Fn::GetAtt'} == set(d.keys())
            return self.resolve_attr(*d['Fn::GetAtt'])
        if 'Fn::Base64' in d:
            assert {'Fn::Base64'} == set(d.keys())
            # keep the base64 for clarity
            return d

        # Thoses metadata can contain cloudformation stuff
        if 'Metadata' in d:
            del d['Metadata']

        if 'Tags' in d:
            d['Tags'] = sorted_dict(d['Tags'] + self._stack_info['Tags'])

        if 'HostedZoneTags' in d:
            d['HostedZoneTags'] = sorted_dict(d['HostedZoneTags'] + self._stack_info['Tags'])

        # some specific things we need to sort
        need_sorted = [
            'SecurityGroups', 'Subnets', 'VPCZoneIdentifier',
            'SecurityGroupIngress', 'SecurityGroupEgress', 'SubnetIds', 'AvailabilityZones',
        ]
        for k in need_sorted:
            if k in d:
                if not d[k]:
                    continue
                if isinstance(d[k][0], dict):
                    d[k] = sorted_dict(d[k])
                else:
                    d[k] = sorted(d[k])

        to_remove = ['DependsOn']
        for k in to_remove:
            if k in d:
                del d[k]

        if 'TTL' in d:
            d['TTL'] = int(d['TTL'])

        # TODO instead of this, having a 'ANY' object in the resource 2 stack.
        # And a step before compare that apply the stack property to the resource.
        # Remove the Comment of record resources, as it's not used
        if 'Type' in d and d['Type'] == 'AWS::Route53::RecordSet' and 'Comment' in d['Properties']:
            del d['Properties']['Comment']

        # Remove the PreferredCacheClusterAZs of CacheClusters
        if 'Type' in d and d['Type'] == 'AWS::ElastiCache::ReplicationGroup' and \
                        'PreferredCacheClusterAZs' in d['Properties']:
            del d['Properties']['PreferredCacheClusterAZs']

        if 'PropagateAtLaunch' in d:
            d['PropagateAtLaunch'] = str(d['PropagateAtLaunch']).lower()

        return d

    def get_processed(self):
        resources = self._template['Resources']
        # Clean the resource output
        res = walk_json(resources, dict_fct=self.walk_dict)

        for k, v in res.items():
            t, p = v['Type'], v['Properties']
            v['Properties'] = self.apply_default(t, p, k)

        return res

    def resolve_attr(self, log_id, attr_name):
        ph_id = self.ref_values[log_id]
        res_type = next(r['ResourceType'] for r in self._resources if r['LogicalResourceId'] == log_id)

        if res_type == 'AWS::ElastiCache::ReplicationGroup':
            res = self._bs.ec.describe_replication_groups(ReplicationGroupId=ph_id)
            if attr_name == 'PrimaryEndPoint.Address':
                return res[0]['NodeGroups'][0]['PrimaryEndpoint']['Address']
            if attr_name == 'PrimaryEndPoint.Port':
                return res[0]['NodeGroups'][0]['PrimaryEndpoint']['Port']

        if res_type == 'AWS::ElasticLoadBalancing::LoadBalancer':
            res = self._bs.elb.describe_load_balancers(LoadBalancerNames=[ph_id])[0]
            if attr_name == 'CanonicalHostedZoneName':
                return res['CanonicalHostedZoneName']
            if attr_name == 'DNSName':
                return res['DNSName']
            if attr_name == 'SourceSecurityGroup.GroupName':
                return res['SourceSecurityGroup']['GroupName']
            if attr_name == 'SourceSecurityGroup.OwnerAlias':
                return res['SourceSecurityGroup']['OwnerAlias']

        assert False, (log_id, attr_name)

    def apply_default(self, res_type, res_properties, res_log_id):

        if res_type == 'AWS::EC2::SecurityGroup':
            json_default(res_properties, [], 'SecurityGroupEgress')
            json_default(res_properties, [], 'SecurityGroupIngress')
            json_default(res_properties, [], 'Tags')

        if res_type == 'AWS::AutoScaling::LaunchConfiguration':
            json_default(res_properties, False, 'EbsOptimized')
            json_default(res_properties, True, 'InstanceMonitoring')
            json_default(res_properties, [], 'SecurityGroups')
            json_default(res_properties, '', 'UserData')
            json_default(res_properties, '', 'RamDiskId')
            json_default(res_properties, '', 'KernelId')
            json_default(res_properties, [], 'BlockDeviceMappings')

        if res_type == 'AWS::ElasticLoadBalancing::LoadBalancer':
            json_default(res_properties, 'internet-facing', 'Scheme')
            json_default(res_properties, {'IdleTimeout': 60}, 'ConnectionSettings')
            json_default(res_properties, [], 'SecurityGroups')
            json_default(res_properties, [], 'Tags')
            json_default(res_properties, self.ref_values[res_log_id], 'LoadBalancerName')
            json_default(res_properties, 'TCP', 'Listeners', '*', 'InstanceProtocol')

        if res_type == 'AWS::AutoScaling::AutoScalingGroup':
            json_default(res_properties, 300, 'Cooldown')
            json_default(res_properties, [], 'LoadBalancerNames')
            json_default(res_properties, [], 'VPCZoneIdentifier')

        if res_type == 'AWS::ElastiCache::ReplicationGroup':
            json_default(res_properties, 6379, 'Port')
            res_properties['CacheSubnetGroupName'] = res_properties['CacheSubnetGroupName'].lower()

        if res_type == 'AWS::CloudWatch::Alarm':
            json_default(res_properties, [], 'InsufficientDataActions')
            json_default(res_properties, [], 'OKActions')
            json_default(res_properties, self.ref_values[res_log_id], 'AlarmName')

        if res_type == 'AWS::AutoScaling::ScalingPolicy':
            json_default(res_properties, 'SimpleScaling', 'PolicyType')
            json_default(res_properties, [], 'StepAdjustments')

        if res_type == 'AWS::EC2::VPC':
            json_default(res_properties, True, 'EnableDnsSupport')
            json_default(res_properties, False, 'EnableDnsHostnames')

        if res_type == 'AWS::Route53::HostedZone':
            if res_properties['Name'][-1] != '.':
                res_properties['Name'] = res_properties['Name'] + '.'

        if res_type == 'AWS::S3::Bucket':
            res_properties['AccessControl'] = self.s3grant2fa(res_properties.get('AccessControl'))

        return res_properties

    def s3grant2fa(self, accessControl):
        """
        Transform a name access control into a full complex access
        Because we can't have the name with the resource, only the complex one, bravo AWS
        """
        all_user_group = {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}
        auth_user_group = {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}
        log_group = {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'}
        owner = {'DisplayName': 'fa', 'ID': 'far', 'Type': 'CanonicalUser'}

        # helpful, even if a lot of cases are not allowed
        def grant(**kwargs):
            return [dict(Grantee=v, Permission=k) for k, v in kwargs.items()]

        if not accessControl:
            return []
        if not isinstance(accessControl, list):
            accessControl = [accessControl]
        res = []

        for ac in accessControl:
            if ac == 'PublicReadWrite':
                # Read for public
                res.extend(grant(FULL_CONTROL=owner, READ=all_user_group, WRITE=all_user_group))
            elif ac == 'Private':
                res.append(grant(FULL_CONTROL=owner))
            elif ac == 'PublicRead':
                res.extend(grant(FULL_CONTROL=owner, READ=all_user_group))
            elif ac == 'AuthenticatedRead':
                res.extend(grant(FULL_CONTROL=owner, READ=auth_user_group))
            elif ac == 'LogDeliveryWrite':
                res.extend(grant(WRITE=log_group, READ_ACP=log_group))
            elif ac == 'BucketOwnerRead' or ac == 'BucketOwnerFullControl':
                pass  # ignored
            else:
                raise Exception('access control not known ' + repr(ac))

        return sorted_dict(res)
