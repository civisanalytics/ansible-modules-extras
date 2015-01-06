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
module: redshift
short_description: create, delete, or modify an Amazon redshift instance
description:
    - Creates, deletes, or modifies redshift instances.
options:
  command:
    description:
      - Specifies the action to take.
    required: true
    default: null
    aliases: []
    choices: [ 'create', 'facts', 'delete', 'modify' ]
  identifier:
    description:
      - Redshift cluster identifier.
    required: true
    default: null
    aliases: []
  node_type:
    description:
      - The node type of the cluster. Must be specified when command=create.
    required: true
    default: null
    aliases: []
    choices: ['dw1.xlarge', 'dw1.8xlarge', 'dw2.large', 'dw2.8xlarge', ]
  username:
    description:
      - Master database username. Used only when command=create.
    required: true
    default: null
    aliases: []
  password:
    description:
      - Master database password. Used only when command=create.
    required: true
    default: null
    aliases: []
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
    aliases: []
  availability_zone:
    description:
      - availability zone in which to launch cluster
    required: false
    default: null
    aliases: ['zone', 'aws_zone']
  number_of_nodes:
    description:
      - Number of nodes. Only used when cluster_type=multi-node.
    required: false
    default: null
    choices: []
  cluster_subnet_group_name:
    description:
      - which subnet to place the cluster
    required: false
    default: null
    aliases: ['subnet']
    choices: []
  cluster_security_groups:
    description:
      - in which security group the cluster belongs
    required: false
    default: null
    aliases: ['security_groups']
    choices: []
  vpc_security_group_ids:
    description:
      - VPC security group
    required: false
    aliases: ['vpc_security_groups']
    choices: []
    default: null
  preferred_maintenance_window:
    description:
      - maintenance window
    required: false
    aliases: ['maintance_window', 'maint_window']
    default: null
    choices: []
  cluster_parameter_group_name:
    description:
      - name of the cluster parameter group
    required: false
    aliases: ['param_group_name']
    choices: []
    default: null
  automated_snapshot_retention_period:
    description:
      - period when the snapshot take place
    required: false
    aliases: ['retention_period']
    choices: []
    default: null
  port:
    description:
      - which port the cluster is listining
    required: false
    default: null
    choices: []
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
    choices: []
    default: null
  number_of_nodes:
    description:
      - number of the nodes the cluster should run
    required: false
    choices: []
    default: null
  publicly_accessible:
    description:
      - if the cluster is accessible publicly or not
    required: false
    choices: []
    default: null
  encrypted:
    description:
      -  if the cluster is encrypted or not
    required: false
    choices: []
    default: null
  elastic_ip:
    description:
      - if the cluster has an elastic IP or not
    required: false
    choices: []
    default: null
  new_cluster_identifier:
    description:
      - Only used when command=modify.
    required: false
    aliases: ['new_identifier']
    choices: []
    default: null
  aws_secret_key:
    description:
      - AWS secret key. If not set then the value of the AWS_SECRET_KEY environment variable is used.
    required: false
    default: null
    aliases: [ 'ec2_secret_key', 'secret_key' ]
  aws_access_key:
    description:
      - AWS access key. If not set then the value of the AWS_ACCESS_KEY environment variable is used.
    required: false
    default: null
    aliases: [ 'ec2_access_key', 'access_key' ]
  wait:
    description:
      - When command=create, modify or restore then wait for the database to enter the 'available' state. When command=delete wait for the database to be terminated.
    required: false
    default: "no"
    choices: [ "yes", "no" ]
    aliases: []
  wait_timeout:
    description:
      - how long before wait gives up, in seconds
    default: 300
    aliases: []

requirements: [ 'boto' ]
author: Jens Carl, Hothead Games Inc.
'''

EXAMPLES = '''
# Basic cluster provisioning example
- redshift: >
    command=create
    node_type=dw1.xlarge
    identifier=new_cluster
    username=cluster_admin
    password=1nsecure
'''

import sys
import time

try:
    import boto.redshift
except:
    print "failed=True msg='boto required for this module'"
    sys.exit(1)


def _collect_facts( resource ):
    """
    Transfrom cluster inforamtion to dict.
    """
    d = {
        'identifier'            : resource['ClusterIdentifier'],
        'create_time'           : resource['ClusterCreateTime'],
        'status'                : resource['ClusterStatus'],
        'username'              : resource['MasterUsername'],
        'db_name'               : resource['DBName'],
        'availability_zone'     : resource['AvailabilityZone'],
        'maintenance_window'    : resource['PreferredMaintenanceWindow'],
    }

    for node in resource['ClusterNodes']:
        if node['NodeRole'] in ('SHARED', 'LEADER'):
            d['private_ip_address'] = node['PrivateIPAddress']
            break

    return d


def create_cluster(module, redshift):
    """
    Create a new cluster

    module: AnsibleModule object
    redshift: authenticated redshift connection object

    Returns:
    """

    identifier      = module.params.get('identifier')
    node_type       = module.params.get('node_type')
    username        = module.params.get('username')
    password        = module.params.get('password')
    wait            = module.params.get('wait')
    wait_timeout    = module.params.get('wait_timeout')

    changed = True
    # Package up the optional parameters
    params = {}
    for p in ( 'db_name', 'cluster_type', 'cluster_security_groups', 'vpc_security_group_ids', 'cluster_subnet_group_name', 'availability_zone', 'preferred_maintenance_window', 'cluster_parameter_group_name', 'automated_snapshot_retention_period', 'port', 'cluster_version', 'allow_version_upgrade', 'number_of_nodes', 'publicly_accessible', 'encrypted', 'elastic_ip' ):
        if module.params.get( p ):
            params[ p ] = module.params.get( p )

    try:
        redshift.describe_clusters(identifier)['DescribeClustersResponse']['DescribeClustersResult']['Clusters'][0]
        changed = False
    except boto.exception.JSONResponseError, e:
        try:
            redshift.create_cluster(identifier, node_type, username, password, **params)
        except boto.exception.JSONResponseError, e:
            # This won't produce a message, until this error
            # https://github.com/boto/boto/issues/2776 is fixed.
            module.fail_json(msg = e.error_message)

    try:
        resource = redshift.describe_clusters(identifier)['DescribeClustersResponse']['DescribeClustersResult']['Clusters'][0]
    except boto.exception.JSONResponseError, e:
        # This won't produce a message, until this error
        # https://github.com/boto/boto/issues/2776 is fixed.
        module.fail_json(msg = e.error_message)

    if wait:
        try:
            wait_timeout = time.time() + wait_timeout
            time.sleep(5)

            while wait_timeout > time.time() and resource['ClusterStatus'] != 'available':
                time.sleep(5)
                if wait_timeout <= time.time():
                    module.fail_json(msg = "Timeout waiting for resource %s" % resource.id)

                resource = redshift.describe_clusters(identifier)['DescribeClustersResponse']['DescribeClustersResult']['Clusters'][0]

        except boto.exception.JSONResponseError, e:
            # This won't produce a message, until this error
            # https://github.com/boto/boto/issues/2776 is fixed.
            module.fail_json(msg = e.error_message)

    return( changed, _collect_facts( resource ) )


def describe_cluster(module, redshift):
    """
    """
    identifier = module.params.get('identifier')

    try:
        resource = redshift.describe_clusters(identifier)['DescribeClustersResponse']['DescribeClustersResult']['Clusters'][0]
    except boto.exception.JSONResponseError, e:
        # This won't produce a message, until this error
        # https://github.com/boto/boto/issues/2776 is fixed.
        module.fail_json(msg = 'Redshift cluster %s does not exist' % identifier)

    return( True, _collect_facts( resource ) )


def delete_cluster(module, redshift):
    """
    Delete a cluster.

    module: Ansible module object
    redshift: authenticated redshift connection object
    """

    identifier      = module.params.get('identifier')
    wait            = module.params.get('wait')
    wait_timeout    = module.params.get('wait_timeout')

    try:
        redshift.delete_custer( identifier )
    except boto.exception.JSONResponseError, e:
        # This won't produce a message, until this error
        # https://github.com/boto/boto/issues/2776 is fixed.
        module.fail_json(msg = e.error_message)

    if wait:
        try:
            wait_timeout = time.time() + wait_timeout
            resource = redshift.describe_clusters(identifier)['DescribeClustersResponse']['DescribeClustersResult']['Clusters'][0]

            while wait_timeout > time.time() and resource['ClusterStatus'] != 'deleting':
                time.sleep(5)
                if wait_timeout <= time.time():
                    module.fail_json(msg = "Timeout waiting for resource %s" % resource.id)

                resource = redshift.describe_clusters(identifier)['DescribeClustersResponse']['DescribeClustersResult']['Clusters'][0]

        except boto.exception.JSONResponseError, e:
            # This won't produce a message, until this error
            # https://github.com/boto/boto/issues/2776 is fixed.
            module.fail_json(msg = e.error_message)

    return( True, {} )


def modify_cluster(module, redshift):
    """
    Modify an existing cluster.

    module: Ansible module object
    redshift: authenticated redshift connection object

    """

    identifier      = module.params.get('identifier')
    wait            = module.params.get('wait')
    wait_timeout    = module.params.get('wait_timeout')

    # Package up the optional parameters
    params = {}
    for p in ( 'cluster_type', 'cluster_security_groups', 'vpc_security_group_ids', 'cluster_subnet_group_name', 'availability_zone', 'preferred_maintenance_window', 'cluster_parameter_group_name', 'automated_snapshot_retention_period', 'port', 'cluster_version', 'allow_version_upgrade', 'number_of_nodes', 'new_cluster_identifier'):
        if module.params.get( p ):
            params[ p ] = module.params.get( p )

    try:
        redshift.describe_clusters(identifier)['DescribeClustersResponse']['DescribeClustersResult']['Clusters'][0]
        changed = False
    except boto.exception.JSONResponseError, e:
        try:
            redshift.modify_cluster(identifier, **params)
        except boto.exception.JSONResponseError, e:
            # This won't produce a message, until this error
            # https://github.com/boto/boto/issues/2776 is fixed.
            module.fail_json(msg = e.error_message)

    try:
        resource = redshift.describe_clusters(identifier)['DescribeClustersResponse']['DescribeClustersResult']['Clusters'][0]
    except boto.exception.JSONResponseError, e:
        # This won't produce a message, until this error
        # https://github.com/boto/boto/issues/2776 is fixed.
        module.fail_json(msg = e.error_message)

    if wait:
        try:
            wait_timeout = time.time() + wait_timeout
            time.sleep(5)

            while wait_timeout > time.time() and resource['ClusterStatus'] != 'available':
                time.sleep(5)
                if wait_timeout <= time.time():
                    module.fail_json(msg = "Timeout waiting for resource %s" % resource.id)

                resource = redshift.describe_clusters(identifier)['DescribeClustersResponse']['DescribeClustersResult']['Clusters'][0]

        except boto.exception.JSONResponseError, e:
            # This won't produce a message, until this error
            # https://github.com/boto/boto/issues/2776 is fixed.
            module.fail_json(msg = e.error_message)

    return( True, _collect_facts( resource ) )


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
            command                             = dict(choices=['create', 'facts', 'delete', 'modify'], required=True),
            identifier                          = dict(required=True),
            node_type                           = dict(choices=['dw1.xlarge', 'dw1.8xlarge', 'dw2.large', 'dw2.8xlarge', ], required=False),
            username                            = dict(required=False),
            password                            = dict(no_log=True, required=False),
            db_name                             = dict(require=False),
            cluster_type                        = dict(choices=['multi-node', 'single-node', ], default='single-node'),
            cluster_security_groups             = dict(aliases=['security_groups'], type='list'),
            vpc_security_group_ids              = dict(aliases=['vpc_security_groups'], type='list'),
            cluster_subnet_group_name           = dict(aliases=['subnet']),
            availability_zone                   = dict(aliases=['aws_zone', 'zone']),
            preferred_maintenance_window        = dict(aliases=['maintance_window', 'maint_window']),
            cluster_parameter_group_name        = dict(aliases=['param_group_name']),
            automated_snapshot_retention_period = dict(aliases=['retention_period']),
            port                                = dict(type='int'),
            cluster_version                     = dict(aliases=['version'], choices=['1.0']),
            allow_version_upgrade               = dict(aliases=['version_upgrade'], type='bool'),
            number_of_nodes                     = dict(type='int'),
            publicly_accessible                 = dict(type='bool'),
            encrypted                           = dict(type='bool'),
            elastic_ip                          = dict(required=False),
            new_cluster_identifier              = dict(aliases=['new_identifier']),
            wait                                = dict(type='bool', default=False),
            wait_timeout                        = dict(default=300),
        )
    )

    module = AnsibleModule(
        argument_spec = argument_spec,
    )

    command = module.params.get('command')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module)
    if not region:
        module.fail_json(msg = str("region not specified and unable to determine region from EC2_REGION."))

    # connect to the rds endpoint
    try:
        conn = connect_to_aws(boto.redshift, region, **aws_connect_params)
    except boto.exception.JSONResponseError, e:
        # This won't produce a message, until this error
        # https://github.com/boto/boto/issues/2776 is fixed.
        module.fail_json(msg = e.error_message)

    changed = True
    if command == 'create':
        (changed, cluster) = create_cluster(module, conn)

    elif command == 'facts':
        (changed, cluster) = describe_cluster(module, conn)

    elif command == 'delete':
        (changed, cluster) = delete_cluster(module, cron)

    elif command == 'modify':
        (changed, cluster) = modify_cluster(module, conn)

    module.exit_json(changed=changed, cluster=cluster)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

main()
