#!/usr/bin/python

# Copyright 2014 Jens Carl, Hothead Games Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


DOCUMENTATION = '''
---
author:
- '"Jens Carl (@j-carl), Hothead Games Inc.'"
- '"Herby Gillot (@herbygillot)"'
module: redshift
short_description: create, delete, or modify an Amazon redshift instance
description:
    - Create, delete, modify and snapshot Amazon Redshift clusters
options:
  command:
    description:
      - Specifies the action to take.
    required: true
    choices: [ 'create', 'facts', 'delete', 'modify', 'snapshot', 'restore' ]
  identifier:
    description:
      - Redshift cluster identifier.
    required: true
  node_type:
    description:
      - The node type of the cluster. Must be specified when command=create.
    required: false
    choices: ['dw1.xlarge', 'dw1.8xlarge', 'dw2.large', 'dw2.8xlarge', 'dc1.large', 'dc1.8xlarge', 'ds2.xlarge', 'ds2.8xlarge', 'ds1.large', 'ds1.8xlarge']
  username:
    description:
      - Master database username. Used only when command=create.
    required: false
  password:
    description:
      - Master database password. Used only when command=create.
    required: true
  cluster_type:
    description:
      - The type of cluster.
    required: false
    choices: ['multi-node', 'single-node' ]
    default: 'single-node'
  db_name:
    description:
      - Name of the database.
    required: False
    default: null
  availability_zone:
    description:
      - availability zone in which to launch cluster
    required: false
    aliases: ['zone', 'aws_zone']
  number_of_nodes:
    description:
      - Number of nodes. Only used when cluster_type=multi-node.
    required: false
    default: null
  cluster_subnet_group_name:
    description:
      - which subnet to place the cluster
    required: false
    aliases: ['subnet']
  cluster_security_groups:
    description:
      - in which security group the cluster belongs
    required: false
    default: null
    aliases: ['security_groups']
  vpc_security_group_ids:
    description:
      - VPC security group
    required: false
    aliases: ['vpc_security_groups']
    default: null
  preferred_maintenance_window:
    description:
      - maintenance window
    required: false
    aliases: ['maintance_window', 'maint_window']
    default: null
  cluster_parameter_group_name:
    description:
      - name of the cluster parameter group
    required: false
    aliases: ['param_group_name']
    default: null
  automated_snapshot_retention_period:
    description:
      - period when the snapshot take place
    required: false
    aliases: ['retention_period']
    default: null
  port:
    description:
      - which port the cluster is listining
    required: false
    default: null
  cluster_version:
    description:
      - which version the cluster should have
    required: false
    aliases: ['version']
    choices: ['1.0']
    default: null
  allow_version_upgrade:
    description:
      - flag to determinate if upgrade of version is possible
    required: false
    aliases: ['version_upgrade']
    default: null
  number_of_nodes:
    description:
      - number of the nodes the cluster should run
    required: false
    default: null
  publicly_accessible:
    description:
      - if the cluster is accessible publicly or not
    required: false
    default: null
  encrypted:
    description:
      -  if the cluster is encrypted or not
    required: false
    default: null
  elastic_ip:
    description:
      - if the cluster has an elastic IP or not
    required: false
    default: null
  new_cluster_identifier:
    description:
      - Only used when command=modify.
    required: false
    aliases: ['new_identifier']
    default: null
  snapshot:
    description:
      - Specifies the source snapshot used when restoring a new cluster from a snapshot (command=restore), or as the snapshot name to save to when creating a new snapshot from a running cluster (command=snapshot)
      - When deleting a cluster, if this is set, a final snapshot will be created and named as per this parameter before the cluster is destroyed
    required: false
    aliases: ['final_snapshot']
    default: null
  owner_account:
    description: Used when command=restore, this is the account of the snapshot to restore from if this is a snapshot you do not own.
    required: false
    default: null
  wait:
    description:
      - When creating, modifying or restoring a cluster, we will wait for the database to enter the 'available' state. When deleting, wait for the database to be terminated.
    required: false
    default: "no"
    choices: [ "yes", "no" ]
  wait_timeout:
    description:
      - How long before wait gives up, in seconds
      - If set to 0, will wait forever
    default: 300
requirements: [ 'boto' ]
extends_documentation_fragment: aws
'''  # noqa


EXAMPLES = '''
# Basic cluster provisioning example
- redshift: >
    command=create
    node_type=dw1.xlarge
    identifier=new_cluster
    username=cluster_admin
    password=1nsecure

# Delete cluster "foobar"
- redshift:
    identifier: 'foobar'
    region:     'us-east-1'
    command:    'delete'

# Create a snapshot from Redshift cluster "cluster1"
# Wait as long as it takes for the snapshotting process to complete
- redshift:
    identifier:   'cluster1'
    region:       'us-east-1'
    snapshot:     'cluster1-snapshot-1'
    command:      'snapshot'
    wait:          yes
    wait_timeout:  0

# Restore a new cluster from the snapshot we just created, and wait up to an
# hour for the operation to complete
- redshift:
    identifier:   'cluster2'
    region:       'us-east-1'
    snapshot:     'cluster1-snapshot-1'
    command:      'restore'
    wait:          yes
    wait_timeout:  3600
'''  # noqa


RETURN = '''
cluster:
    description: dictionary containing all the cluster information
    returned: success
    type: dictionary
    contains:
        identifier:
            description: Id of the cluster.
            returned: success
            type: string
            sample: "new_redshift_cluster"
        create_time:
            description: Time of the cluster creation as timestamp.
            returned: success
            type: float
            sample: 1430158536.308
        status:
            description: Stutus of the cluster.
            returned: success
            type: string
            sample: "available"
        db_name:
            description: Name of the database.
            returned: success
            type: string
            sample: "new_db_name"
        node_type:
            description: the cluster's type
            returned: success
            type: string
            sample: "ds2.xlarge"
        availability_zone:
            description: Amazon availability zone where the cluster is located.
            returned: success
            type: string
            sample: "us-east-1b"
        maintenance_window:
            description: Time frame when maintenance/upgrade are done.
            returned: success
            type: string
            sample: "sun:09:30-sun:10:00"
        private_ip_address:
            description: Private IP address of the main node.
            returned: success
            type: string
            sample: "10.10.10.10"
        public_ip_address:
            description: Public IP address of the main node.
            returned: success
            type: string
            sample: "0.0.0.0"
        public_key:
            description: the SSH public key of the cluster
            returned: success
            type: string
            sample: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbd+acx3...."
        node_count:
            description: the number of nodes in this cluster
            returned: success
            type: int
            sample: 12
        parameter_groups:
            description: list of parameter groups enabled for this cluster
            returned: success
            type: list
            sample: [{'ClusterParameterStatusList': None, 'ParameterApplyStatus': 'in-sync', 'ParameterGroupName': 'my-parameter-group'}]
        security_groups:
            description list of security groups enabled for this cluster
            returned: success
            type: list
            sample: [{'ClusterSecurityGroupName': 'prod', 'Status': 'active'}]
        vpc_id:
            description: the ID of the VPC the cluster is in
            returned: success
            type: string
            sample: "vpc-12345678"
        tags:
            description: list of key/value dicts for each tag pair set in the cluster
            returned: success
            type: list
            sample: [{"Key": "environment", "Value": "production"}]
        address:
            description: address of cluster endpoint
            returned: success
            type: string
            sample: "new-redshift_cluster.jfkdjfdkj.us-east-1.redshift.amazonaws.com"
        port:
            description: service port of cluster
            returned: success
            type: int
            sample: 5439
        kms_key_id:
            description: KMS Key ID used to encrypt the database
            returned: success
            type: string
            sample: "arn:aws:kms:us-east-1:123456789012:key/fdsfa89f-32ff-3333-fdsd-3r2f3ifdsoif"
'''  # noqa


from functools import partial
import time


CHECK_MODE = False


try:
    import boto.exception
    import boto.redshift
    HAS_BOTO = True
except:
    HAS_BOTO = False


def _collect_facts(resource):
    """Transfrom cluster information to dict."""
    facts = {
        'identifier':         resource.get('ClusterIdentifier'),
        'create_time':        resource.get('ClusterCreateTime'),
        'status':             resource.get('ClusterStatus'),
        'username':           resource.get('MasterUsername'),
        'db_name':            resource.get('DBName'),
        'availability_zone':  resource.get('AvailabilityZone'),
        'maintenance_window': resource.get('PreferredMaintenanceWindow'),
        'node_type':          resource.get('NodeType'),
        'public_key':         resource.get('ClusterPublicKey'),
        'node_count':         resource.get('NumberOfNodes'),
        'modify_status':      resource.get('ModifyStatus'),
        'restore_status':     resource.get('RestoreStatus'),
        'vpc_id':             resource.get('VpcId'),
        'tags':               resource.get('Tags'),
        'kms_key_id':         resource.get('KmsKeyId'),
        'parameter_groups':   resource.get('ClusterParameterGroups'),
        'security_groups':    resource.get('ClusterSecurityGroups'),
        'endpoint':           resource.get('Endpoint'),
    }

    for node in resource['ClusterNodes']:
        if node['NodeRole'] in ('SHARED', 'LEADER'):
            facts['private_ip_address'] = node.get('PrivateIPAddress')
            facts['public_ip_address'] = node.get('PublicIPAddress')
            break

    if resource.get('Endpoint') and isinstance(resource['Endpoint'], dict):
        for c in ('Address', 'Port'):
            facts[c.lower()] = resource.get('Endpoint', {}).get(c)
    return facts


def is_not_found_json_response_error(error):
    """
    Return True if the given JSONResponseError means the resource can't be
    found
    """
    return (error.status == 404) or (error.reason.lower() == 'not found')


def create_cluster(module, redshift):
    """
    Create a new cluster

    module: AnsibleModule object
    redshift: authenticated redshift connection object

    Returns:
    """

    identifier = module.params.get('identifier')
    node_type = module.params.get('node_type')
    username = module.params.get('username')
    password = module.params.get('password')
    wait = module.params.get('wait')
    wait_timeout = module.params.get('wait_timeout')

    if not node_type:
        module.fail_json(
            msg='node_type must be specified when creating a cluster.')

    create_params = ('db_name',
                     'cluster_type',
                     'cluster_security_groups',
                     'vpc_security_group_ids',
                     'cluster_subnet_group_name',
                     'availability_zone',
                     'preferred_maintenance_window',
                     'cluster_parameter_group_name',
                     'automated_snapshot_retention_period',
                     'port',
                     'cluster_version',
                     'allow_version_upgrade',
                     'number_of_nodes',
                     'publicly_accessible',
                     'encrypted',
                     'elastic_ip')

    params = {}

    for p in create_params:
        prm = module.params.get(p)
        if prm:
            params[p] = prm

    if check_cluster_exists(redshift, identifier):
        return describe_cluster(module, redshift)

    if CHECK_MODE:
        return (True, {})

    try:
        redshift.create_cluster(
            identifier, node_type, username, password, **params)
    except boto.exception.JSONResponseError, e:
        module.fail_json(msg=json_response_err_msg(e))

    if wait:
        check_exists = partial(check_resource_status, redshift, identifier)
        if not wait_for_condition(check_exists, wait_timeout):
            module.fail_json(
                msg='Timed out while creating cluster "{}"'.format(identifier))

    (_, cluster) = describe_cluster(module, redshift)
    return (True, cluster)


def describe_cluster(module, redshift):
    """
    Describe a specified cluster.

    module: Ansible module object
    redshift: authenticated redshift connection object
    """
    identifier = module.params.get('identifier')
    resource = None

    try:
        resource = get_cluster(redshift, identifier)
    except boto.exception.JSONResponseError, e:
        module.fail_json(msg=json_response_err_msg(e))

    return(False, _collect_facts(resource))


def delete_cluster(module, redshift):
    """
    Delete a cluster.

    module: Ansible module object
    redshift: authenticated redshift connection object
    """

    identifier = module.params.get('identifier')
    snapshot = module.params.get('snapshot')
    wait = module.params.get('wait')
    wait_timeout = module.params.get('wait_timeout')

    if check_cluster_absent(redshift, identifier):
        return (False, {})

    if CHECK_MODE:
        return (True, {})

    if snapshot:
        args = {'final_cluster_snapshot_identifier': snapshot,
                'skip_final_cluster_snapshot': False}
    else:
        args = {'skip_final_cluster_snapshot': True}

    try:
        redshift.delete_cluster(identifier, **args)
    except boto.exception.JSONResponseError, e:
        module.fail_json(msg=json_response_err_msg(e))

    if wait:
        is_absent = partial(check_cluster_absent, redshift, identifier)
        if not wait_for_condition(is_absent, wait_timeout):
            module.fail_json(
                msg='Timed out while deleting cluster {}'.format(identifier))

    return(True, {})


def modify_cluster(module, redshift):
    """
    Modify an existing cluster.

    module: Ansible module object
    redshift: authenticated redshift connection object
    """

    identifier = module.params.get('identifier')
    wait = module.params.get('wait')
    wait_timeout = module.params.get('wait_timeout')

    modify_params = ('cluster_type',
                     'cluster_security_groups',
                     'vpc_security_group_ids',
                     'cluster_subnet_group_name',
                     'availability_zone',
                     'preferred_maintenance_window',
                     'cluster_parameter_group_name',
                     'automated_snapshot_retention_period',
                     'cluster_version',
                     'allow_version_upgrade',
                     'number_of_nodes',
                     'node_type',
                     'new_cluster_identifier')

    if CHECK_MODE:
        return (True, describe_cluster(module, redshift)[1])

    params = {}
    for p in modify_params:
        prm = module.params.get(p)
        if prm:
            params[p] = prm

    if module.params.get('password'):
        params['master_user_password'] = module.params.get('password')

    try:
        redshift.modify_cluster(identifier, **params)
    except boto.exception.JSONResponseError, e:
        module.fail_json(msg=json_response_err_msg(e))

    if wait:
        check_status = partial(check_resource_status, redshift, identifier)
        if not wait_for_condition(check_status, wait_timeout):
            module.fail_json(
                msg='Timed out waiting for cluster modification to complete.')

    (_, cluster) = describe_cluster(module, redshift)
    return(True, cluster)


def snapshot_cluster(module, redshift):
    """
    Take a snapshot of a cluster

    module: AnsibleModule object
    redshift: authenticated redshift connection object

    Returns:
    """
    identifier = module.params.get('identifier')
    snapshot = module.params.get('snapshot')
    wait = module.params.get('wait')
    wait_timeout = module.params.get('wait_timeout')

    snapshot_present = False

    if not snapshot:
        module.fail_json(msg='Snapshot must be specified')

    try:
        snapshot_present = check_snapshot_exists(redshift, snapshot)
    except boto.exception.JSONResponseError, e:
        module.fail_json(msg=json_response_err_msg(e))

    if snapshot_present:
        return describe_cluster(module, redshift)

    if CHECK_MODE:
        return (True, describe_cluster(module, redshift)[1])

    try:
        redshift.create_cluster_snapshot(snapshot, identifier)
    except boto.exception.JSONResponseError, e:
        module.fail_json(msg=json_response_err_msg(e))

    if wait:
        check_status = partial(check_resource_status, redshift, snapshot,
                               resource_type='snapshot')
        if not wait_for_condition(check_status, wait_timeout):
            module.fail_json(
                msg='Timed out waiting for snapshotting cluster {}'
                    .format(identifier))

    (_, cluster_info) = describe_cluster(module, redshift)
    return (True, cluster_info)


def restore_cluster(module, redshift):
    """
    Restore a new cluster from a given snapshot

    module: AnsibleModule object
    redshift: authenticated redshift connection object

    Returns:
    """
    identifier = module.params.get('identifier')
    snapshot = module.params.get('snapshot')
    wait = module.params.get('wait')
    wait_timeout = module.params.get('wait_timeout')

    restore_params = ('allow_version_upgrade',
                      'automated_snapshot_retention_period',
                      'availability_zone',
                      'cluster_parameter_group_name',
                      'cluster_security_groups',
                      'cluster_subnet_group_name',
                      'elastic_ip',
                      'owner_account',
                      'port',
                      'preferred_maintenance_window',
                      'publicly_accessible',
                      'vpc_security_group_ids')

    params = {}
    for p in restore_params:
        prm = module.params.get(p)
        if prm:
            params[p] = prm

    if not snapshot:
        module.fail_json(msg='Snapshot is required')

    if check_cluster_exists(redshift, identifier):
        return describe_cluster(module, redshift)

    if CHECK_MODE:
        return (True, describe_cluster(module, redshift)[1])

    try:
        redshift.restore_from_cluster_snapshot(identifier, snapshot, **params)
    except boto.exception.JSONResponseError, e:
        module.fail_json(msg=json_response_err_msg(e))

    if wait:
        check_status = partial(check_resource_status, redshift, identifier)
        if not wait_for_condition(check_status, wait_timeout):
            module.fail_json(
                msg='Timed out waiting for cluster restore to complete.')

    (_, cluster_info) = describe_cluster(module, redshift)
    return (True, cluster_info)


def get_cluster(redshift, identifier):
    """
    Given an identifier, return the dictionary representing the identified
    Redshift cluster, or None otherwise
    """
    response = redshift.describe_clusters(identifier)
    cluster = (response['DescribeClustersResponse']
                       ['DescribeClustersResult']
                       ['Clusters'])
    return cluster[0] if cluster else None


def get_snapshot(redshift, identifier):
    """
    Given an identifier, return the dictionary representing the identified
    Redshift snapshot, or None otherwise
    """
    response = redshift.describe_cluster_snapshots(
        snapshot_identifier=identifier)
    snapshot = (response['DescribeClusterSnapshotsResponse']
                        ['DescribeClusterSnapshotsResult']
                        ['Snapshots'])
    return snapshot[0] if snapshot else None


def check_cluster_exists(redshift, identifier):
    """
    Return True if a cluster is absent, False otherwise.
    """
    return check_resource_exists(redshift, identifier)


def check_cluster_absent(redshift, identifier):
    return not check_cluster_exists(redshift, identifier)


def check_resource_exists(redshift, identifier, resource_type='cluster'):

    if resource_type == 'cluster':
        fetch = get_cluster
    elif resource_type == 'snapshot':
        fetch = get_snapshot
    else:
        raise ValueError(
            'Unrecognized resource type: {}'.format(resource_type))

    resource = None

    try:
        resource = fetch(redshift, identifier)
    except boto.exception.JSONResponseError, e:
        if is_not_found_json_response_error(e):
            return False

    return bool(resource)


def check_resource_status(redshift, identifier, resource_type='cluster',
                          desired_status='available'):
    """
    Return True if the cluster has the given desired status, False otherwise
    """
    has_status = False

    resource = None
    status_field = None

    if resource_type == 'cluster':
        fetch = get_cluster
        status_field = 'ClusterStatus'
    elif resource_type == 'snapshot':
        fetch = get_snapshot
        status_field = 'Status'
    else:
        raise ValueError(
            'Unrecognized resource type: {}'.format(resource_type))
    try:
        resource = fetch(redshift, identifier)
    except boto.exception.JSONResponseError, e:
        if is_not_found_json_response_error(e):
            pass

    if not resource:
        pass

    if resource and (resource.get(status_field) == desired_status):
        has_status = True

    return has_status


def check_snapshot_exists(redshift, snapshot_identifier):
    """
    Return True if the given snapshot exists, False otherwise
    """
    return check_resource_exists(redshift, snapshot_identifier,
                                 resource_type='snapshot')


def wait_for_condition(condition_check, timeout):
    """
    Given a callable representing a check for some condition, wait until the
    condition is met, within some maxiumum amount of time (timeout).

    The given condition_check callable is expected to return True when the
    condition is met, False otherwise.

    Timeout is the maxiumum number of seconds to wait.

    If timeout is set to 0, then we will wait forever.

    Returns:
    - True: condition was met within the timeout period
    - False: reached timeout and the condition was still not met
    """
    wait_timeout = time.time() + timeout

    if timeout == 0:
        def time_check(): return True
    else:
        def time_check(): return wait_timeout > time.time()

    while time_check():
        if condition_check():
            return True
        time.sleep(5)

    return False


def json_response_err_msg(json_response_error):
    """ Given a JSONResponseError from boto, return the error message. """
    err_msg = None

    if hasattr(json_response_error, 'body') and json_response_error.body:
        if type(json_response_error.body) in types.StringTypes:
            err_msg = json_response_error.body
        elif isinstance(json_response_error.body, dict):
            err_msg = json_response_error.body.get('Error', {}).get('Message')

    if not err_msg:
        err_msg = str(json_response_error)
    return err_msg


def main():
    global CHECK_MODE

    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(

        command=dict(choices=['create', 'facts', 'delete', 'modify',
                                'snapshot', 'restore'], required=True),

        identifier=dict(required=True),

        # NOTE: dw1.* and dw2.* cluster types have been deprecated
        node_type=dict(choices=['dw1.xlarge', 'dw1.8xlarge', 'dw2.large',
                                  'dw2.8xlarge', 'dc1.large', 'dc1.8xlarge',
                                  'ds2.xlarge', 'ds2.8xlarge', 'ds1.large',
                                  'ds1.8xlarge'], required=False),

        username=dict(required=False),

        password=dict(no_log=True, required=False),

        db_name=dict(required=False),

        cluster_type=dict(choices=['multi-node', 'single-node'], default='single-node'),  # noqa

        cluster_security_groups=dict(aliases=['security_groups'], type='list'),  # noqa

        vpc_security_group_ids=dict(aliases=['vpc_security_groups'], type='list'),  # noqa

        cluster_subnet_group_name=dict(aliases=['subnet']),

        availability_zone=dict(aliases=['aws_zone', 'zone']),

        preferred_maintenance_window=dict(aliases=['maintance_window', 'maint_window']),  # noqa

        cluster_parameter_group_name=dict(aliases=['param_group_name']),

        port=dict(type='int'),

        cluster_version=dict(aliases=['version'], choices=['1.0']),

        allow_version_upgrade=dict(aliases=['version_upgrade'], type='bool'),

        number_of_nodes=dict(type='int'),

        publicly_accessible=dict(type='bool'),

        encrypted=dict(type='bool'),

        elastic_ip=dict(required=False),

        new_cluster_identifier=dict(aliases=['new_identifier']),

        snapshot=dict(aliases=['final_snapshot'], required=False),

        wait=dict(type='bool', default=False),

        wait_timeout=dict(type='int', default=300),

        owner_account=dict(require=False),

        automated_snapshot_retention_period=dict(aliases=['retention_period']),

        )
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    if not HAS_BOTO:
        module.fail_json(msg='boto v2.9.0+ required for this module')

    CHECK_MODE = module.check_mode

    command = module.params.get('command')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module)
    if not region:
        module.fail_json(
            msg=("Region not specified; unable to determine region from "
                 "EC2_REGION."))

    # connect to the redshift endpoint
    try:
        conn = connect_to_aws(boto.redshift, region, **aws_connect_params)
    except boto.exception.JSONResponseError, e:
        module.fail_json(msg=json_response_err_msg(e))

    changed = False

    if command == 'create':
        (changed, cluster) = create_cluster(module, conn)

    elif command == 'facts':
        (changed, cluster) = describe_cluster(module, conn)

    elif command == 'delete':
        (changed, cluster) = delete_cluster(module, conn)

    elif command == 'modify':
        (changed, cluster) = modify_cluster(module, conn)

    elif command == 'snapshot':
        (changed, cluster) = snapshot_cluster(module, conn)

    elif command == 'restore':
        (changed, cluster) = restore_cluster(module, conn)

    module.exit_json(changed=changed, cluster=cluster)


# import module snippets
from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.ec2 import *    # noqa


if __name__ == '__main__':
    main()
