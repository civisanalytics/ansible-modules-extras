#!/usr/bin/python

# Copyright 2015 Herby Gillot
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
module: redshift_snapshots
short_description: List, tag and clean up Amazon Redshift snapshots
description:
    - This module can list snapshots for Amazon's Redshift service.
    - Snapshots can be listed by Redshift cluster, creation time, size and/or tags
    - This module only lists, tags and deletes snapshots.  To create Redshift snapshots, use the redshift module with the "snapshot" command.
version_added: "2.0"
options:
    command:
      description:
        - Specifies the action to take. If none specified, lists snapshots by default.
        - 'list' lists all snapshots, or as per provided filters
        - 'facts' is the same as 'list'
        - 'copy' enables copying an automated snapshot into a new manual snapshot. When a cluster is destroyed, its automated snapshots are usually destroyed with it, so this is useful to back up automated snapshots in such a case.
        - 'delete' deletes the named or matching snapshot(s)
      required: false
      default:  list
      choices:  [ 'list', 'facts', 'copy', 'delete' ]
    cluster:
      description:
        - The Redshift cluster whose snapshots to use
        - Focuses all actions on only snapshots belonging to this cluster, in addition to other specified filters
        - Cannot be specified together with the "snapshot" parameter
      required: false
      default:  null
      aliases:
        - 'identifier'
        - 'instance'
    cluster_pattern:
      description:
        - Filter for snapshots whose origin cluster's name matches this pattern
      required: false
      default:  null
    name:
      description:
        - Redshift snapshot name for operating on a specific snapshot
        - Cannot be specified together with the "cluster" parameter
      aliases:
        - 'snapshot'
        - 'source'
      required: false
      default:  null
    name_pattern:
      description:
        - Regular expression that is used to filter through snapshot names
      required: false
      default:  null
    dest:
      description:
        - Name of new snapshot to copy to when command=copy
      required: false
      default: null
    snapshot_type:
      description:
        - Filter for only snapshots created from a Redshift cluster of this type
      required: false
      default:  null
    start_time:
      description:
        - Filter for only snapshots created after this date
        - Date and time values should be specified in YYYY-MM-DD format, or YYYY-MM-DD'T'HH:MM
      required: false
      default:  null
    end_time:
      description:
        - Filter for only snapshots created before this date
        - Date and time values should be specified in YYYY-MM-DD format, or YYYY-MM-DD'T'HH:MM
      required: false
      default:  null
    force:
      description:
        - If copying and the destination snapshot exists, delete it so that the copy can proceed
      required: false
      default:  false
    greater_than_mb:
      description:
        - Filter for only snapshots larger than the given value in megabytes.
        - Must be specified as a decimal (1.0, 0.0, 5.5, etc.)
      required: false
      default:  null
    less_than_mb:
      description:
        - Filter for only snapshots smaller than the given value in megabytes.
        - Must be specified as a decimal (1.0, 0.0, 5.5, etc.)
      required: false
      default:  null
    sort_by:
      description:
        - Return field to sort snapshots on.
      required: false
      default:  'create_time_epoch'
    reverse_sort:
      description:
        - If set to True, reverses the sort direction
      required: false
      default:  false
    tags:
      description:
        - Dictionary of tags key/values to filter snapshots by
      required: false
      default:  null
    wait:
      description:
        - If set to True, waits for operations to complete
      required: false
      default:  false
    wait_timeout:
      description:
        - The amount of time in seconds to wait for operations, if wait is enabled
      required: false
      default:  300
author: '"Herby Gillot (@herbygillot)"'
requirements: [ 'boto' ]
extends_documentation_fragment: aws
'''  # noqa


EXAMPLES = '''
# List all Redshift snapshots in us-east-1
- redshift_snapshots:
    region:   'us-east-1'


# List all snapshots created from cluster "mycluster"
- redshift_snapshots:
    cluster:  'mycluster'
    region:   'us-east-1'


# List all snapshots tagged with "environment": "ext11"
- redshift_snapshots:
    region:   'us-east-1'
    tags:
      environment:  'ext11'


# List all snapshots created after Dec. 1, 2015, and larger than 500 gigs
- redshift_snapshots:
    region:   'us-east-1'
    tags:
      environment:  'ext11'
    start_time:     '2015-12-01'
    larger_than_mb: 500000


# List all snaphosts whose name starts with "mycluster"
- name: 'List snapshots'
  redshift_snapshots:
    name_pattern:   '^mycluster.*'
    region:         'us-east-1'


- name: Delete snapshot "foobaz"
  redshift_snapshots:
    name:    'foobaz'
    region:  'us-east-1'
    command: 'delete'


# Copy an automated snapshot to 'backup1', forcibly deleting 'backup1' if it
# already exists.  (Without force, this will fail with an error about 'backup1'
# being already present.)
- name: "Copy an automated snapshot from mycluster to 'backup1'"
  register: copy_snapshot
  redshift_snapshots:
      source:       'rs:mycluster-2015-01-01-15-02-41'
      dest:         'backup1'
      command:      'copy'
      force:        True
      region:       'us-east-1'

'''  # noqa


RETURN = '''
snapshots:
    description: list containing a facts dict for each affected/matching snapshot
    returned: success
    type: list
    contains:
        name:
            description: name of the snapshot
            returned: success
            type: string
            sample: "snapshot1"
        availability_zone:
            description: availability zone of this snapshot's source cluster
            returned: success
            type: string
            sample: "us-east-1"
        cluster:
            description: name of the cluster this snapshot was created from
            returned: success
            type: string
            sample: "cluster1"
        snapshot_type:
            description: type of snapshot (manual or automated)
            returned: success
            type: string
            sample: "manual"
        tags:
            description: dictionary of tag key/values for this snapshot
            returned: success
            type: dict
            sample: {'foo': 'bar'}
        vpc_id:
            description: ID of VPC of this snapshot's cluster, if it is in one
            returned: success
            type: string
            sample: "vpc-12345672"
        db_name:
            description: Name of the database
            returned: success
            type: string
            sample: "maindb"
        is_encrypted:
            description: Whether or not the snapshot is of an encrypted cluster
            returned: success
            type: boolean
            sample: True
        is_encrypted_with_hsm:
            description: Whether or not the encryption is done with via HSM
            returned: success
            type: boolean
            sample: True
        node_type:
            description: Node type of this snapshot's cluster
            returned: success
            type: string
            sample: "ds2.xlarge"
        node_count:
            description: Number of nodes in the snapshot's cluster
            returned: success
            type: int
            sample: 25
        port:
            description: Service port of the snapshot's cluster
            returned: success
            type: int
            sample: 5439
        restorable_node_types:
            description: List of node types this snapshot can restore to
            returned: success
            type: list
            sample: [ "ds2.xlarge", "ds1.xlarge" ]
        status:
            description: Status of the snapshot
            returned: success
            type: string
            sample: "available"
        total_size_mb:
            description: Size of the snapshot in megabytes
            returned: success
            type: float
            sample: 4231342.50
        owner_account:
            description: The ID of the account that owns this snapshot
            returned: success
            type: string
            sample: "123456789123"
        master_user:
            description: The name of the database account for this snapshot
            returned: success
            type: string
            sample: "dbadmin"
        cluster_version:
            description: The version of the Redshift snapshot's origin cluster
            returned: success
            type: string
            sample: "1.0"
        kms_key_id:
            description: The ID of the KMS Key used to encrypt this snapshot
            returned: success
            type: string
            sample: "arn...."
        elapsed_seconds:
            description: How many seconds it took to create the snapshot.
            returned: success
            type: int
            sample: 272
        create_time_epoch:
            description: The time the snapshot was created, in seconds since epoch
            returned: success
            type: float
            sample: 1449675208.545
        create_time:
            description: The time the snapshot was created, as an ISO 8601 timestamp
            returned: success
            type: string
            sample: "2015-12-09T10:33:28.545000"
        accounts_with_restore_access:
            description: The list of dictionaries specific accounts that have restore access to this snapshot
            returned: success
            type: list
            example: [ {"AccountId": "123456778901" } ]
'''  # noqa


from datetime import datetime
from numbers import Number
from operator import itemgetter
from types import StringTypes
import time
import re

try:
    import boto
    import boto.redshift
    HAS_BOTO = True
except:
    HAS_BOTO = False


class RedshiftSnapshotsModule(object):

    def __init__(self, module):
        self.module = module
        self.dry_run = self.module.check_mode
        self.params = self.module.params

        self.wait_enabled = self.module.params.get('wait')
        self.timeout = self.module.params.get('wait_timeout')

        region, _, conn_params = get_aws_connection_info(self.module)

        if not region:
            self.module.fail_json(
                msg='Region not specified; unable to determine AWS region')
        try:
            self.conn = connect_to_aws(boto.redshift, region, **conn_params)
        except boto.exception.JSONResponseError, e:
            msg = ('Could create Redshift API connection: {}'
                   .format(json_response_err_msg(e)))
            self.module.fail_json(msg=msg)

        self._setup_filters()

    def _setup_filters(self):
        """
        Set up snapshot filters as per configured filter options
        """
        self.filters = []

        if self.params.get('less_than_mb'):
            def lt_test(val):
                return val < float(self.params.get('less_than_mb'))
            self.filters.append(
                create_typed_field_filter('total_size_mb', lt_test, float))

        if self.params.get('greater_than_mb'):
            def gt_test(val):
                return val > float(self.params.get('greater_than_mb'))
            self.filters.append(
                create_typed_field_filter('total_size_mb', gt_test, float))

        if self.params.get('tags'):
            tags = self.params.get('tags')
            for tag in tags:
                self.filters.append(create_tag_filter(tag, tags[tag]))

        if self.params.get('name_pattern'):
            self._add_field_pattern_filter('name_pattern', 'name')

        if self.params.get('cluster_pattern'):
            self._add_field_pattern_filter('cluster_pattern', 'cluster')

    def _add_field_pattern_filter(self, pattern_field, field):
        pattern = self.params.get(pattern_field)
        try:
            pattern_test = create_regex_field_filter(field, pattern)
        except re.error, e:
            msg = ('Error using {field} pattern: {error}'
                   .format(field=field, error=e.message))
            self.module.fail_json(msg=msg)

        self.filters.append(pattern_test)

    def delete_cmd(self):
        """
        Deletes snapshots matching configured filters and properties.

        Returns a module results dictionary with the following content:
        - 'changed': (bool) True if any snapshots were or would be deleted
        - 'snapshots': (list) list of snapshots affected
        """
        snapshots = self.list_matching()

        if not snapshots:
            return unchanged(snapshots)

        for snapshot in snapshots:
            self.delete(snapshot['name'])

        if self.wait_enabled:
            def check(): return self.list_matching() == []
            if not wait_for_condition(check, self.timeout):
                self.module.fail_json(
                    msg='Timed out waiting for snapshots to be deleted.')

        return changed(snapshots)

    def facts_cmd(self):
        return self.list_cmd()

    def list_cmd(self):
        """
        Lists snapshots as per configured filters and properties, sorting them
        as per 'sort_by'

        Returns a module results dictionary with the following content:
        - 'changed': (bool) whether any changes were made, always False
        - 'snapshots': (list) list of snapshot fact dicts
        """
        return unchanged(self.list_matching())

    def copy_cmd(self):
        """
        Copies an automated snapshot into a manual one
        """
        source = self.params.get('name')
        dest = self.params.get('dest')
        force = self.params.get('force')

        affected_snapshots = list()

        if not source:
            self.module.fail_json(
                msg=('Snapshot name (source or snapshot) was not specified. '
                     'This parameter is required as the source snapshot to '
                     'copy from.'))

        if not dest:
            self.module.fail_json(
                msg=('Destination (dest) was not specified.  This is required '
                     'if copying as the destination snapshot to copy to.'))

        try:
            src_snapshot = self.get(source)
        except boto.exception.JSONResponseError, e:
            self.module.fail_json(msg=json_response_err_msg(e))

        dest_snapshot = self.get(dest, ignore_missing=True)
        src_cluster = src_snapshot.get('cluster')

        if dest_snapshot and force:
            self.delete(dest)

        if self.dry_run:
            return changed(affected_snapshots)

        try:
            self.conn.copy_cluster_snapshot(
                source, dest, source_snapshot_cluster_identifier=src_cluster)
        except boto.exception.JSONResponseError, e:
            msg = ('Error while copying snapshot from "{src}" to "{dst}": {e}'
                   .format(src=source, dst=dest, e=json_response_err_msg(e)))
            self.module.fail_json(msg=msg)

        if self.wait_enabled:
            def check():
                target = self.get(dest, ignore_missing=True)
                if target and (target.get('status') == 'available'):
                    return True
                return False
            if not wait_for_condition(check, self.timeout):
                self.module.fail_json(
                    msg='Timed out waiting for snapshot copy to complete.')

        affected_snapshots.append(self.get(dest))

        return changed(affected_snapshots)

    def run_command(self):
        command = self.params.get('command')
        cmd_call = '{}_cmd'.format(self.params.get('command', ''))

        if hasattr(self, cmd_call):
            return getattr(self, cmd_call)()
        else:
            self.module.fail_json(msg='Unknown cmd_call: {}'.format(command))

    def delete(self, snapshot_id):
        """
        Given a snapshot identifier, delete it if we are not running in
        dry-run mode.
        """
        if not self.dry_run:
            try:
                self.conn.delete_cluster_snapshot(snapshot_id)
            except boto.exception.JSONResponseError, e:
                msg = ('Failed to delete snapshot "{}": {}'
                       .format(snapshot_id, json_response_err_msg(e)))
                self.module.fail_json(msg=msg)

    def get(self, snapshot_id, ignore_missing=False):
        """
        Given a snapshot identifier, return that snapshot's fact dict.

        If ignore_missing is set to True, returns None instead of raising
        an exception when the requested snapshot isn't present.

        Returns:
        - snapshot fact dict

        Raises:
        - boto.exception.JSONResponseError
        """
        snapshot = None

        try:
            response = self.conn.describe_cluster_snapshots(
                snapshot_identifier=snapshot_id)
            snapshot = (response['DescribeClusterSnapshotsResponse']
                                ['DescribeClusterSnapshotsResult']
                                ['Snapshots'][0])
        except boto.exception.JSONResponseError, e:
            if is_not_found_json_response_error(e) and ignore_missing:
                pass
            else:
                raise

        if snapshot:
            snapshot = snapshot_fact(snapshot)

        return snapshot

    def exists(self, snapshot_name):
        """
        Given a snapshot name, return True if it exists, False otherwise

        Raises:
        - boto.exception.JSONResponseError
        """
        return bool(self.get_snapshot(snapshot_name, ignore_missing=True))

    def list_matching(self):
        """
        Return a list of snapshot fact dicts matching configured filters
        """
        sort_by = self.params.get('sort_by')

        list_params = ('snapshot_type', 'start_time', 'end_time')

        marker = 1  # batch retrieval marker, start at 1 as "default" case,

        snapshots = list()

        params = {}
        for p in list_params:
            prm = self.params.get(p)
            if prm:
                params[p] = prm

        if self.params.get('cluster'):
            params['cluster_identifier'] = self.params['cluster']

        if self.params.get('name'):
            params['snapshot_identifier'] = self.params['name']

        response = None

        while marker:
            if marker != 1:
                params.update({'marker': marker})

            try:
                response = self.conn.describe_cluster_snapshots(**params)
            except boto.exception.JSONResponseError, e:
                if is_not_found_json_response_error(e):
                    break
                else:
                    self.module.fail_json(msg=json_response_err_msg(e))

            snapshots.extend((response['DescribeClusterSnapshotsResponse']
                                      ['DescribeClusterSnapshotsResult']
                                      ['Snapshots']))

            marker = (response['DescribeClusterSnapshotsResponse']
                              ['DescribeClusterSnapshotsResult']
                              ['Marker'])

        results = map(snapshot_fact, snapshots)

        if self.filters:
            def test_snapshot(snapshot):
                return all(map(lambda _filtr: _filtr(snapshot), self.filters))
            results = filter(test_snapshot, results)

        sort_key = itemgetter(sort_by)

        try:
            results = sorted(results, key=sort_key,
                             reverse=self.module.params.get('reverse_sort'))
        except KeyError:
            self.module.fail_json(
                msg='Cannot sort on unknown field: {}'.format(sort_by))

        return results


def create_tag_filter(key, value):
    """
    Given a key and a value, create a callable that returns True if the
    given snapshot contains this key and value in its tags.
    """
    def _filter_tag(snapshot):
        snap_tags = [frozenset(t.items()) for t in snapshot.get("tags", [])]
        target = frozenset({"Key": key, "Value": value}.items())
        return target in snap_tags

    return _filter_tag


def create_regex_field_filter(field_name, regex):
    """
    Return a callable that checks the value of the given value against the
    specified regular expression.
    """
    pattern = re.compile(regex)

    def _regex_filter(s):
        return bool(re.search(pattern, s.get(field_name, '')))

    return _regex_filter


def create_typed_field_filter(field_name, filter_call, field_type):
    """
    Return a callable that applies the given filter call against the value
    of the snapshot fact field, after this value has been casted into the
    specified type
    """
    def _filter(snapshot):
        return filter_call(field_type(snapshot.get(field_name)))

    return _filter


def is_not_found_json_response_error(error):
    """
    Return True if the given JSONResponseError means the resource can't be
    found
    """
    return (error.status == 404) or (error.reason.lower() == 'not found')


def json_response_err_msg(json_response_error):
    """ Given a JSONResponseError from boto, return the error message. """
    err_msg = None

    if hasattr(json_response_error, 'body') and json_response_error.body:
        if type(json_response_error.body) in StringTypes:
            err_msg = json_response_error.body
        elif isinstance(json_response_error.body, dict):
            err_msg = json_response_error.body.get('Error', {}).get('Message')

    if not err_msg:
        err_msg = str(json_response_error)
    return err_msg


def snapshot_fact(snapshot):
    """
    Given a snapshot dictionary returned by the AWS Redshift API,
    return a subset to be used as a facts dict
    """
    facts = {
            'availability_zone':  snapshot.get('AvailabilityZone'),
            'cluster':            snapshot.get('ClusterIdentifier'),
            'name':               snapshot.get('SnapshotIdentifier'),
            'snapshot_type':      snapshot.get('SnapshotType'),
            'tags':               snapshot.get('Tags'),
            'vpc_id':             snapshot.get('VpcId'),
            'db_name':            snapshot.get('DBName'),
            'is_encrypted':       snapshot.get('Encrypted'),
            'is_encrypted_with_hsm': snapshot.get('EncryptedWithHSM'),
            'node_type':          snapshot.get('NodeType'),
            'node_count':         snapshot.get('NumberOfNodes'),
            'port':               snapshot.get('Port'),
            'restorable_node_types': snapshot.get('RestorableNodeTypes'),
            'status':             snapshot.get('Status'),
            'total_size_mb':      snapshot.get('TotalBackupSizeInMegaBytes'),
            'owner_account':      snapshot.get('OwnerAccount'),
            'master_user':        snapshot.get('MasterUsername'),
            'cluster_version':    snapshot.get('ClusterVersion'),
            'kms_key_id':         snapshot.get('KmsKeyId'),
            'elapsed_seconds':    snapshot.get('ElapsedTimeInSeconds'),
            'create_time_epoch':  snapshot.get('SnapshotCreateTime'),

            'create_time': to_iso_time_str(snapshot.get('SnapshotCreateTime')),

            'accounts_with_restore_access':
                snapshot.get('AccountsWithRestoreAccess'),  # noqa
        }

    return facts


def to_iso_time_str(timestamp):
    if not timestamp:
        return

    elif isinstance(timestamp, datetime):
        t = timestamp

    elif isinstance(timestamp, Number):
        # assuming that if this is numeric, then it's seconds since epoch
        t = datetime.fromtimestamp(timestamp)

    return t.isoformat()


def results_dict(snapshots, changed=False):
    """
    Return the Ansible module results dictionary
    """
    return {'changed': changed, 'snapshots': snapshots}


def changed(snapshots):
    return results_dict(snapshots, changed=True)


def unchanged(snapshots):
    return results_dict(snapshots, changed=False)


def wait_for_condition(condition_check, timeout, interval=3):
    """
    Given a callable representing a check for some condition, wait until the
    condition is met, within some maxiumum amount of time (timeout).

    The given condition_check callable is expected to return True when the
    condition is met, False otherwise.

    Timeout is the maxiumum number of seconds to wait.

    If timeout is set to 0, then we will wait forever.

    The condition check will be performed every (interval) seconds, which is
    3 by default.

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
        time.sleep(interval)

    return False


def main():
    argument_spec = ec2_argument_spec()

    argument_spec.update(dict(
            command=dict(choices=['list', 'facts', 'copy', 'delete'],
                         default='list', required=False),

            cluster=dict(required=False, aliases=['identifier', 'instance']),

            cluster_pattern=dict(required=False),

            name=dict(required=False, aliases=['snapshot', 'source']),

            name_pattern=dict(required=False),

            dest=dict(required=False, aliases=['new_snapshot']),

            force=dict(required=False, type='bool', default=False),

            snapshot_type=dict(required=False),

            start_time=dict(required=False),

            end_time=dict(required=False),

            greater_than_mb=dict(required=False, type='float'),

            less_than_mb=dict(required=False, type='float'),

            sort_by=dict(required=False, default='create_time_epoch'),

            reverse_sort=dict(required=False, type='bool', default=False),

            tags=dict(required=False, type='dict'),

            wait=dict(required=False, type='bool', default=False),

            wait_timeout=dict(required=False, type='int', default=300),
        ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           mutually_exclusive=['cluster', 'snapshot'])

    redshift_module = RedshiftSnapshotsModule(module)

    result_dict = redshift_module.run_command()

    module.exit_json(**result_dict)


# import module snippets
from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.ec2 import *    # noqa


if __name__ == '__main__':
    main()
