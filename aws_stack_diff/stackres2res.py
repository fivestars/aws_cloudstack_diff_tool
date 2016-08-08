#!/usr/bin/env python3
"""
Inside this code is a lot of frustration and sweats. The AWS api is nowhere near internal coherency.
Getting info from element are sometimes straightforward. Those times are four leaves clovers, cherish these memories.
Each time I implement a new element, I discover a new way of doing things.
"""

from __future__ import unicode_literals, print_function

from itertools import chain

import jsonpath_rw
from aws_stack_diff.nullable_json import clean_null, NULL
from aws_stack_diff.utils import walk_json, sorted_dict
from botocore.exceptions import ClientError


# Very special value that mean : remove that key in a dictionnary or list

def pf(path, j):
    return list(r.value for r in jsonpath_rw.parse(path).find(j))


def stackres2res(boto_session, stack_name, stack_res):
    return Stack2Res(boto_session, stack_name, stack_res).get_processed()


def filter_tags(tags):
    """
    Some tags are given by the stack, remove that
    """
    stack_tag = {'aws:cloudformation:stack-id', 'aws:cloudformation:stack-name', 'aws:cloudformation:logical-id'}
    return sorted_dict(t for t in tags if t['Key'] not in stack_tag)


class Stack2Res(object):
    NO_PH_RESOURCES = '<NO PHYSICAL RESOURCE ID>'

    def __init__(self, boto_session, stack_name, stack_res):
        self._bs = boto_session
        self._stack_name = stack_name

        self.__stack_res = stack_res  # in the rare case we want to access the stack infos

        self._resources = self._bs.cf.describe_stack_resources(StackName=stack_name)

    def cleaning_NULL(self, json):
        # def walk_json(e, dict_fct=i, list_fct=i, num_fct=i, str_fct=i, bool_fct=i, null_fct=i):
        def dict_proc(d):
            return {k: v for k, v in d.items() if v is not NULL and k is not NULL}

        def list_proc(l):
            return [e for e in l if e is not NULL]

        def not_found(e):
            return e

        res = walk_json(json, dict_fct=dict_proc, list_fct=list_proc, not_found=not_found)
        return res

    def process_ressource(self, resource):
        ph_id = resource.get('PhysicalResourceId', self.NO_PH_RESOURCES)
        if ph_id == self.NO_PH_RESOURCES:
            return None  # Happens when the state of the stack is failed deleted
        r_type = resource['ResourceType']

        fct_name = r_type.replace('::', '_').replace('AWS_', 'aws_')

        fct = getattr(self, fct_name)
        properties = fct(ph_id, resource)
        if properties == NULL:
            return NULL
        return {
            "Type": r_type,
            "Properties": self.cleaning_NULL(properties),
        }

    def get_processed(self):
        res = {r['LogicalResourceId']: self.process_ressource(r) for r in self._resources}
        return self.cleaning_NULL(res)

    ##############
    # Types functions
    ##############


    def aws_EC2_SubnetRouteTableAssociation(self, ph_id, resource):
        filter = {'association.route-table-association-id': ph_id}
        try:
            all_asso = self._bs.ec2.describe_route_tables(Filters=filter)[0]['Associations']
        except IndexError:
            return NULL
        my_asso = next(a for a in all_asso if a['RouteTableAssociationId'] == ph_id)
        return {
            "RouteTableId": my_asso['RouteTableId'],
            "SubnetId": my_asso['SubnetId'],
        }

    def aws_EC2_NetworkAcl(self, ph_id, resource):
        try:
            acl = self._bs.ec2.describe_network_acls(NetworkAclIds=[ph_id])[0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidNetworkAclID.NotFound':
                return NULL
            raise
        return {
            "VpcId": acl['VpcId'],
            "Tags": filter_tags(acl['Tags']),
        }

    def aws_Route53_HostedZone(self, ph_id, resource):
        hz = self._bs.r53.get_hosted_zone(Id=ph_id)
        tags = self._bs.r53.list_tags_for_resources(ResourceType='hostedzone', ResourceIds=[ph_id])[0]['Tags']
        comment = hz['HostedZone']['Config'].get('Comment')
        return {
            "HostedZoneConfig": {'Comment': comment} if comment else {},
            "HostedZoneTags": filter_tags(tags),
            "Name": hz['HostedZone']['Name'],
            "VPCs": hz['VPCs']
        }

    def aws_ElastiCache_ReplicationGroup(self, ph_id, resource):
        rg = self._bs.ec.describe_replication_groups(ReplicationGroupId=ph_id)[0]
        cache_cluster_ids = pf('NodeGroups.[*].NodeGroupMembers.[*].CacheClusterId', rg)
        all_cc = list(
            chain(*[self._bs.ec.describe_cache_clusters(CacheClusterId=cc_id) for cc_id in cache_cluster_ids]))

        def cc(path):
            res = sorted(set(c[path] for c in all_cc))
            return res[0] if len(res) == 1 else res

        def unified(e):
            e = list(e)
            return e[0] if len(e) == 1 else e

        return {
            "AutomaticFailoverEnabled": 'true' if rg['AutomaticFailover'] != 'disabled' else 'false',
            "AutoMinorVersionUpgrade": cc('AutoMinorVersionUpgrade') and NULL,
            "CacheNodeType": cc('CacheNodeType'),
            # "CacheParameterGroupName": cc_001['CacheSubnetGroupName'],
            # "CacheSecurityGroupNames": [String, ...],
            "CacheSubnetGroupName": cc('CacheSubnetGroupName'),
            "Engine": cc('Engine'),
            "EngineVersion": cc('EngineVersion'),
            # "NotificationTopicArn": String,
            "NumCacheClusters": len(rg['NodeGroups'][0]['NodeGroupMembers']),
            "Port": unified(pf('NodeGroups.[*].PrimaryEndpoint.Port', rg)),
            # "PreferredCacheClusterAZs": [String, ...],
            "PreferredMaintenanceWindow": cc('PreferredMaintenanceWindow'),
            "ReplicationGroupDescription": rg['Description'],
            "SecurityGroupIds": list(set(pf('[*].SecurityGroups.[*].SecurityGroupId', all_cc))),
            # "SnapshotArns": [String, ...],
            "SnapshotRetentionLimit": max(*pf('[*].SnapshotRetentionLimit', all_cc)),
            # "SnapshotWindow": cc_001['SnapshotWindow'], # can be choosen by the system when maintenance window is not specified
        }

    def aws_Route53_RecordSet(self, ph_id, resource):
        # AWS sucks big this time, not being able to get which record set it's been created for
        # I'm forced to calculate which record set it comes from and to infer that the hostedZone didn't changed
        hosted_zone = self.__stack_res[resource['LogicalResourceId']]['Properties']['HostedZoneId']
        rs_res = self._bs.r53.list_resource_record_sets(HostedZoneId=hosted_zone, StartRecordName=ph_id, MaxItems='1')
        rs = rs_res['ResourceRecordSets'][0]

        def resource_records():
            if rs['Type'] == 'CNAME':
                return [rr['Value'] for rr in rs['ResourceRecords']]
            assert False

        return {
            # "AliasTarget": AliasTarget,
            "Comment": NULL,  # There is now way to get the comment back
            # "Failover": String,
            # "GeoLocation": {GeoLocation},
            # "HealthCheckId": String,
            "HostedZoneId": hosted_zone,
            # "HostedZoneName": String,
            "Name": rs['Name'],
            # "Region": String,
            "ResourceRecords": resource_records(),
            # "SetIdentifier": String,
            "TTL": rs['TTL'],
            "Type": rs['Type'],
            # "Weight": Integer
        }

    def aws_AutoScaling_AutoScalingGroup(self, ph_id, resource):
        try:
            asg = self._bs.autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[ph_id])[0]
        except IndexError:
            return NULL

        policies = self._bs.autoscaling.describe_policies(AutoScalingGroupName=ph_id)
        have_static_size = 'ChangeInCapacity' not in set(p['AdjustmentType'] for p in policies)

        def clean_tag(t):
            return dict(Key=t['Key'], PropagateAtLaunch=str(t['PropagateAtLaunch']).lower(), Value=t['Value'])

        vpc_zones = sorted(asg['VPCZoneIdentifier'].split(',')) if asg['VPCZoneIdentifier'].strip() else []

        # the calculation for Desired capacity is a bit complex, as having scaling policy will change it
        desired_capacity = asg['DesiredCapacity']
        if not have_static_size:
            # Get the one from the stack
            stack_asg_prop = self.__stack_res[resource['LogicalResourceId']]['Properties']
            desired_capacity = stack_asg_prop.get('DesiredCapacity', NULL)

        assert not asg['EnabledMetrics']  # no supported
        return dict(
            AvailabilityZones=sorted(asg['AvailabilityZones']) if not vpc_zones else NULL,
            Cooldown=asg['DefaultCooldown'],
            HealthCheckGracePeriod=asg['HealthCheckGracePeriod'],
            HealthCheckType=asg['HealthCheckType'],
            InstanceId=NULL,  # don't put it because instances are created
            LaunchConfigurationName=asg['LaunchConfigurationName'],
            LoadBalancerNames=sorted(asg['LoadBalancerNames']),
            # The desired capacity may change when we have asg rules
            DesiredCapacity=desired_capacity,
            MaxSize=asg['MaxSize'],
            MinSize=asg['MinSize'],
            # "MetricsCollection": [MetricsCollection, ...]
            # "NotificationConfigurations": [NotificationConfigurations, ...],
            # "PlacementGroup": String,
            Tags=filter_tags(map(clean_tag, asg['Tags'])),
            # "TerminationPolicies": [String, ..., ],
            VPCZoneIdentifier=vpc_zones,

            # not in template, but if modified must know
            SuspendedProcesses=sorted_dict(asg['SuspendedProcesses']) or NULL,
        )

    def aws_ElastiCache_SubnetGroup(self, ph_id, resource):
        ecsg = self._bs.ec.describe_cache_subnet_groups(CacheSubnetGroupName=ph_id)[0]
        return {
            "Description": ecsg['CacheSubnetGroupDescription'],
            "SubnetIds": sorted(sn['SubnetIdentifier'] for sn in ecsg['Subnets'])
        }

    def aws_ElasticLoadBalancing_LoadBalancer(self, ph_id, resource):
        try:
            elb = self._bs.elb.describe_load_balancers(LoadBalancerNames=[ph_id])[0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'LoadBalancerNotFound':
                return NULL
            raise

        elb_attr = self._bs.elb.describe_load_balancer_attributes(LoadBalancerName=ph_id)
        elb_tags = self._bs.elb.describe_tags(LoadBalancerNames=[ph_id])[0]
        conn_draining = elb_attr['ConnectionDraining']
        subnets, avai_zones = sorted(elb.get('Subnets', [])) or NULL, sorted(elb.get('AvailabilityZones', [])) or NULL

        return {
            "Instances": NULL,  # not processing because ASG change this one
            "AvailabilityZones": avai_zones if subnets == NULL else NULL,  # Only if not subnets
            "Subnets": subnets,
            "Scheme": elb['Scheme'],
            "AccessLoggingPolicy": elb_attr['AccessLog'] if elb_attr['AccessLog']['Enabled'] else NULL,
            # "AppCookieStickinessPolicy": [AppCookieStickinessPolicy, ...],
            "ConnectionDrainingPolicy": conn_draining if conn_draining['Enabled'] else NULL,
            "ConnectionSettings": elb_attr['ConnectionSettings'],
            "CrossZone": "true" if elb_attr['CrossZoneLoadBalancing']['Enabled'] else NULL,
            "HealthCheck": elb['HealthCheck'],
            # "LBCookieStickinessPolicy": [LBCookieStickinessPolicy, ...],
            "LoadBalancerName": elb['LoadBalancerName'],
            "Listeners": sorted_dict(l['Listener'] for l in elb['ListenerDescriptions']),
            # "Policies": [ElasticLoadBalancing Policy, ...],
            "SecurityGroups": sorted(elb['SecurityGroups']),
            "Tags": filter_tags(elb_tags['Tags']),
        }

    def aws_AutoScaling_LaunchConfiguration(self, ph_id, resource):
        try:
            lc = self._bs.autoscaling.describe_launch_configurations(LaunchConfigurationNames=[ph_id])[0]
        except IndexError:
            return NULL

        return {
            # "AssociatePublicIpAddress": Boolean,
            "BlockDeviceMappings": lc['BlockDeviceMappings'],
            # "ClassicLinkVPCId": String,
            "ClassicLinkVPCSecurityGroups": sorted(lc['ClassicLinkVPCSecurityGroups']) or NULL,
            "EbsOptimized": lc['EbsOptimized'],
            # "IamInstanceProfile": String,
            "ImageId": lc['ImageId'],
            # "InstanceId": String,
            "InstanceMonitoring": lc['InstanceMonitoring']['Enabled'],  # default is true
            "InstanceType": lc['InstanceType'],
            "KernelId": lc['KernelId'],
            "KeyName": lc['KeyName'],
            # "PlacementTenancy": String,
            "RamDiskId": lc['RamdiskId'],
            "SecurityGroups": sorted(lc['SecurityGroups']),
            # "SpotPrice": String,
            "UserData": lc['UserData'],
        }

    def aws_EC2_SecurityGroup(self, ph_id, resource):
        try:
            if ph_id.startswith('sg-'):
                sg = self._bs.ec2.describe_security_groups(GroupIds=[ph_id])[0]
            else:
                sg = self._bs.ec2.describe_security_groups(GroupNames=[ph_id])[0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                return NULL
            raise

        EMPTY_SG_EGRESS = {'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'UserIdGroupPairs': [],
                           'PrefixListIds': []}

        def ingress_process(i):
            res = {
                "ToPort": i['ToPort'],
                "FromPort": i['FromPort'],
                "IpProtocol": i['IpProtocol'],
                "CidrIp": next(iter(i['IpRanges']), {}).get('CidrIp', NULL),
            }

            ssg = (i['UserIdGroupPairs'] + [{}])[0]
            if ssg.get('GroupName') == 'amazon-elb-sg':  # special group, bravo AWS !
                res['SourceSecurityGroupName'], res['SourceSecurityGroupOwnerId'] = 'amazon-elb-sg', 'amazon-elb'
            elif ssg.get('GroupId'):
                res['SourceSecurityGroupId'] = ssg.get('GroupId')

            return res

        def egress_process(i):
            if i == EMPTY_SG_EGRESS:
                return NULL
            assert len(i['IpRanges']) <= 1
            return dict(
                FromPort=i.get('FromPort', NULL),
                CidrIp=next(iter(i['IpRanges']), {}).get('CidrIp', NULL),
                IpProtocol=i['IpProtocol'],
                ToPort=i.get('ToPort', NULL),
                DestinationSecurityGroupId=(i['UserIdGroupPairs'] + [{}])[0].get('GroupId', NULL),
            )

        ingress = [ingress_process(i) for i in sg['IpPermissions']]
        egress = [egress_process(e) for e in sg['IpPermissionsEgress']]

        return dict(
            GroupDescription=sg['Description'],
            SecurityGroupEgress=sorted_dict(clean_null([e for e in egress if e is not NULL])),
            SecurityGroupIngress=sorted_dict(clean_null([i for i in ingress if i is not NULL])),
            Tags=filter_tags(sg['Tags']),
            VpcId=sg.get('VpcId', NULL),
        )

    def aws_CloudWatch_Alarm(self, ph_id, resource):
        try:
            cw = self._bs.cloudwatch.describe_alarms(AlarmNames=[ph_id])[0]
        except IndexError:
            return NULL

        return dict(
            ActionsEnabled=str(cw['ActionsEnabled']).lower(),
            AlarmActions=cw['AlarmActions'],
            # "AlarmDescription": String,
            AlarmName=cw['AlarmName'],
            ComparisonOperator=cw['ComparisonOperator'],
            Dimensions=cw['Dimensions'],
            EvaluationPeriods=cw['EvaluationPeriods'],
            InsufficientDataActions=cw['InsufficientDataActions'],
            MetricName=cw['MetricName'],
            Namespace=cw['Namespace'],
            OKActions=cw['OKActions'],
            Period=cw['Period'],
            Statistic=cw['Statistic'],
            Threshold=int(cw['Threshold']) if float(cw['Threshold']) == int(cw['Threshold']) else cw['Threshold'],
            # "Unit": String
        )

    def aws_AutoScaling_ScalingPolicy(self, ph_id, resource):
        try:
            sp = self._bs.autoscaling.describe_policies(PolicyNames=[ph_id])[0]
        except IndexError:
            return NULL

        return dict(
            AdjustmentType=sp['AdjustmentType'],
            AutoScalingGroupName=sp['AutoScalingGroupName'],
            # "Cooldown": String,
            # "EstimatedInstanceWarmup": Integer,
            # "MetricAggregationType": String,
            # "MinAdjustmentMagnitude": Integer,
            PolicyType=sp['PolicyType'],
            ScalingAdjustment=sp['ScalingAdjustment'],
            StepAdjustments=sp['StepAdjustments'],
        )

    def aws_EC2_InternetGateway(self, ph_id, resource):
        try:
            ig = self._bs.ec2.describe_internet_gateways(InternetGatewayIds=[ph_id])[0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInternetGatewayID.NotFound':
                return NULL
            raise

        return dict(
            Tags=filter_tags(ig['Tags']),
        )

    def aws_EC2_VPCGatewayAttachment(self, ph_id, resource):
        # There is no way I found (AWS is a mess, I mean i) to get the attachment info from the ph_id.
        # So we hope it's the one that exists
        ig_id = self.__stack_res[resource['LogicalResourceId']]['Properties']['InternetGatewayId']
        try:
            ig = self._bs.ec2.describe_internet_gateways(InternetGatewayIds=[ig_id])[0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInternetGatewayID.NotFound':
                return NULL
            raise

        assert len(ig['Attachments']) == 1

        return dict(
            InternetGatewayId=ig['InternetGatewayId'],
            VpcId=ig['Attachments'][0]['VpcId'],
            VpnGatewayId=NULL,  # not used now
        )

    def aws_EC2_EIP(self, ph_id, resource):
        try:
            eip = self._bs.ec2.describe_addresses(PublicIps=[ph_id])[0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAddress.NotFound':
                return NULL
            raise

        return {
            # "InstanceId": String,
            "Domain": eip['Domain'],
        }

    def aws_EC2_Subnet(self, ph_id, resource):
        try:
            sn = self._bs.ec2.describe_subnets(SubnetIds=[ph_id])[0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidSubnetID.NotFound':
                return NULL
            raise

        return dict(
            AvailabilityZone=sn['AvailabilityZone'],
            CidrBlock=sn['CidrBlock'],
            MapPublicIpOnLaunch=str(sn['MapPublicIpOnLaunch']).lower(),
            Tags=filter_tags(sn['Tags']),
            VpcId=sn['VpcId'],
        )

    def aws_EC2_Route(self, ph_id, resource):
        rt_id = self.__stack_res[resource['LogicalResourceId']]['Properties']['RouteTableId']
        rt_cidr = self.__stack_res[resource['LogicalResourceId']]['Properties']['DestinationCidrBlock']
        try:
            routes = self._bs.ec2.describe_route_tables(RouteTableIds=[rt_id])[0]['Routes']
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidRouteTableID.NotFound':
                return NULL
            raise

        cur_route = list(r for r in routes if r['DestinationCidrBlock'] == rt_cidr)[0]

        return dict(
            DestinationCidrBlock=cur_route['DestinationCidrBlock'],
            GatewayId=cur_route.get('GatewayId', NULL),
            InstanceId=cur_route.get('InstanceId', NULL),
            NatGatewayId=cur_route.get('NatGatewayId', NULL),
            NetworkInterfaceId=cur_route.get('NetworkInterfaceId', NULL),
            RouteTableId=rt_id,
            VpcPeeringConnectionId=cur_route.get('VpcPeeringConnectionId', NULL),
        )

    def aws_EC2_RouteTable(self, ph_id, resource):
        try:
            rt = self._bs.ec2.describe_route_tables(RouteTableIds=[ph_id])[0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidRouteTableID.NotFound':
                return NULL
            raise

        return dict(
            VpcId=rt['VpcId'],
            Tags=filter_tags(rt['Tags']),
        )

    def aws_S3_Bucket(self, ph_id, resource):
        try:
            b_ac = self._bs.s3.get_bucket_acl(Bucket=ph_id)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucket':
                return NULL
            raise

        b_tags = self._bs.s3.get_bucket_tagging(Bucket=ph_id)

        def process_grant(g):
            """Really just anonymizing the user full control"""
            if g['Grantee']['Type'] == 'CanonicalUser' \
                    and g['Permission'] == 'FULL_CONTROL':
                g['Grantee']['DisplayName'] = 'fa'
                g['Grantee']['ID'] = 'far'
            return g

        return dict(
            AccessControl=sorted_dict(map(process_grant, b_ac['Grants'])),
            # http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html
            BucketName=ph_id,
            # "CorsConfiguration": CORS Configuration,
            # "LifecycleConfiguration": Lifecycle Configuration,
            # "LoggingConfiguration": Logging Configuration,
            # "NotificationConfiguration": Notification Configuration,
            # "ReplicationConfiguration": Replication Configuration,
            Tags=filter_tags(b_tags),
            # "VersioningConfiguration": Versioning Configuration,
            # "WebsiteConfiguration": Website Configuration
            # Type
        )

    def aws_EC2_VPC(self, ph_id, resource):
        try:
            vpc = self._bs.ec2.describe_vpcs(VpcIds=[ph_id])[0]
            enableDnsSupport = self._bs.ec2.describe_vpc_attribute(VpcId=ph_id, Attribute='enableDnsSupport')
            enableDnsHostnames = self._bs.ec2.describe_vpc_attribute(VpcId=ph_id, Attribute='enableDnsHostnames')
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidVpcID.NotFound':
                return NULL
            raise

        return dict(
            CidrBlock=vpc['CidrBlock'],
            EnableDnsSupport=str(enableDnsSupport['EnableDnsSupport']['Value']).lower(),
            EnableDnsHostnames=str(enableDnsHostnames['EnableDnsHostnames']['Value']).lower(),
            InstanceTenancy=vpc['InstanceTenancy'],
            Tags=filter_tags(vpc['Tags']),
        )
