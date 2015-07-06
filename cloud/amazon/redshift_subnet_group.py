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
author: '"Jens Carl (@j-carl)", Hothead Games Inc.'
module: redshift_subnet_group
short_description: mange Redshift cluster subnet groups
description:
    - Create, modifies, and deletes Redshift cluster subnet groups.
options:
  state:
    description:
      - Specifies whether the subnet should be present or absent.
    default: 'present'
    choices: ['present', 'absent' ]
  group_name:
    description:
      - Cluster subnet group name.
    required: true
    aliases: ['name']
  group_description:
    description:
      - Database subnet group description.
    required: false
    default: null
    aliases: ['description']
  group_subnets:
    description:
      - List of subnet IDs that make up the cluster subnet group.
    required: false
    default: null
    aliases: ['subnets']
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
requirements: [ 'boto' ]
'''

EXAMPLES = '''
# Create a Redshift subnet group
- local_action:
    module: redshift_subnet_group
    state: present
    group_name: redshift-subnet
    group_description: Redshift subnet
    group_subnets:
        - 'subnet-aaaaa'
        - 'subnet-bbbbb'

# Remove subnet group
redshift_subnet_group: >
    state: absent
    group_name: redshift-subnet
'''


try:
    import boto
    from boto import redshift
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
            state             = dict(required=True, choices=['present', 'absent']),
            group_name        = dict(required=True, aliases=['name']),
            group_description = dict(required=False, aliases=['description']),
            group_subnets     = dict(required=False, aliases=['subnets'], type='list'),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO:
        module.fail_json(msg='boto v2.9.0+ required for this module')

    state             = module.params.get('state')
    group_name        = module.params.get('group_name')
    group_description = module.params.get('group_description')
    group_subnets     = module.params.get('group_subnets')

    if state == 'present':
        for required in ('group_name', 'group_description', 'group_subnets'):
            if not module.params.get( required ):
                module.fail_json(msg = str("parameter %s required for state='present'" % required))
    else:
        for not_allowed in ('group_description', 'group_subnets'):
            if module.params.get( not_allowed ):
                module.fail_json(msg = str("parameter %s not allowed for state='absent'" % not_allowed))

    region, ec2_url, aws_connect_params = get_aws_connection_info(module)
    if not region:
        module.fail_json(msg = str("region not specified and unable to determine region from EC2_REGION."))

    # Connect to the Redshift endpoint.
    try:
        conn = connect_to_aws(boto.redshift, region, **aws_connect_params)
    except boto.exception.JSONResponseError, e:
        # FIXME: Change this to just set the error message when
        # https://github.com/boto/boto/issues/2776 is fixed.
        module.fail_json(msg = str(e))

    try:
        changed = False
        exists = False

        try:
            matching_groups = conn.describe_cluster_subnet_groups(group_name, max_records = 100)
            exists = len(matching_groups) > 0
        except boto.exception.JSONResponseError, e:
            # This is a workaround, until this error
            # https://github.com/boto/boto/issues/2776 is fixed.
            if e.body['Error']['Code'] != 'ClusterSubnetGroupNotFoundFault':
            #if e.code != 'ClusterSubnetGroupNotFoundFault':
                module.fail_json(msg = str(e))

        if state == 'absent':
            if exists:
                conn.delete_cluster_subnet_group(group_name)
                changed = True

        else:
            if not exists:
                new_group = conn.create_cluster_subnet_group(group_name, group_description, group_subnets)
            else:
                changed_group = conn.modify_cluster_subnet_group(group_name, group_subnets, description=group_description)
            changed = True

    except boto.exception.JSONResponseError, e:
        # FIXME: Change this to just set the error message when
        # https://github.com/boto/boto/issues/2776 is fixed.
        module.fail_json(msg = str(e))

    module.exit_json(changed=changed)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()