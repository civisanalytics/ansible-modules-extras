#!/usr/bin/python

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
        - 'tag' ensures that the given tags are present on the named or matching snapshot(s)
        - 'delete' deletes the named or matching snapshot(s)
      required: false
      default:  list
      choices:  [ 'list', 'facts', 'tag', 'delete' ]
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
    snapshot:
      description:
        - Redshift snapshot name for operating on a specific snapshot
        - Cannot be specified together with the "cluster" parameter
      required: false
      default:  null
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
    tags:
      description:
        - Dictionary of tags to values.
        - If command=list, filter for snapshots with these tags.
        - If command=tag, these are the tags to be applied to the matching snapshots.
      required: false
      default:  null
author: "Herby Gillot"
'''  # noqa


EXAMPLES = '''
'''  # noqa


RETURN = '''
'''  # noqa


from datetime import datetime
from numbers import Number
from operator import itemgetter
from types import StringTypes


try:
    import boto
    import boto.redshift
    HAS_BOTO = True
except:
    HAS_BOTO = False


class RedshiftSnapshotsModule(object):

    def __init__(self, module):
        self.changed = False
        self.module = module
        self.params = self.module.params

        self.dry_run = self.module.check_mode
        region, _, conn_params = get_aws_connection_info(self.module)

        if not region:
            self.fail_json(
                msg='Region not specified; unable to determine AWS region')
        try:
            self.conn = connect_to_aws(boto.redshift, region, **conn_params)
        except boto.exception.JSONResponseError, e:
            module.fail_json(msg=json_response_err_msg(e))

        self._setup_filters()

    def _setup_filters(self):
        """
        Set up snapshot filters as per configured filter criteria
        """
        self.filters = []

        if self.params.get('less_than_mb'):
            def test(val):
                return val < float(self.params.get('less_than_mb'))
            self.filters.append(
                create_numeric_field_filter(
                    'TotalBackupSizeInMegaBytes', test))

        if self.params.get('greater_than_mb'):
            def test(val):
                return val > float(self.params.get('greater_than_mb'))
            self.filters.append(
                create_numeric_field_filter(
                    'TotalBackupSizeInMegaBytes', test))

        if (self.params.get('command') in ('list', 'facts')) \
                and self.params.get('tags'):
            tags = self.params.get('tags')
            for tag in tags:
                self.filters.append(create_tag_filter(tag, tags[tag]))

    def list_snapshots(self):
        """
        Return a list of snapshot dictionaries as per configured filters
        and attributes
        """
        get_params = ('snapshot_type', 'start_time', 'end_time')

        marker = 1  # batch retrieval marker, start at 1 as "default" case,
        snapshots = list()

        params = \
            {k: self.params[k] for k in get_params if self.params.get(k)}

        if self.params.get('cluster'):
            params['cluster_identifier'] = self.params['cluster']

        if self.params.get('snapshot'):
            params['snapshot_identifier'] = self.params['snapshot']

        args = params.copy()
        response = None

        while marker:
            if marker != 1:
                args.update({'marker': marker})

            try:
                response = self.conn.describe_cluster_snapshots(**args)
            except boto.exception.JSONResponseError, e:
                self.module.fail_json(msg=json_response_err_msg(e))

            snapshots.extend((response['DescribeClusterSnapshotsResponse']
                                      ['DescribeClusterSnapshotsResult']
                                      ['Snapshots']))

            marker = (response['DescribeClusterSnapshotsResponse']
                              ['DescribeClusterSnapshotsResult']
                              ['Marker'])

        if self.filters:
            def test_snapshot(snapshot):
                return all(map(lambda f: f(snapshot), self.filters))
            results = filter(test_snapshot, snapshots)
        else:
            results = snapshots

        return results

    def delete_command(self):
        """
        Deletes snapshots matching configured filters and properties.

        Returns a module results dictionary with the following content:
        - 'changed': (bool) True if any snapshots were or would be deleted
        - 'snapshots': (list) list of snapshots affected
        """
        snapshots = self.list_snapshots()

        if not snapshots:
            return {'changed': False, 'snapshots': []}

        for snapshot in snapshots:
            if not self.dry_run:
                try:
                    self.conn.delete_cluster_snapshot(snapshot['Identifier'])
                except boto.exception.JSONResponseError, e:
                    self.module.fail_json(msg=json_response_err_msg(e))

        return {'changed': True, 'snapshots': get_snapshot_facts(snapshots)}

    def facts_command(self):
        return self.list_command()

    def list_command(self):
        """
        Lists snapshots as per configured filters and properties, sorting them
        as per 'sort_by'

        Returns a module results dictionary with the following content:
        - 'changed': (bool) whether any changes were made, always False
        - 'snapshots': (list) list of snapshot fact dicts
        """
        sort_field = self.params.get('sort_by')
        sort_method = itemgetter(sort_field)

        snapshots = get_snapshot_facts(self.list_snapshots())
        try:
            results = sorted(snapshots, key=sort_method)
        except KeyError:
            self.module.fail_json(
                msg='Cannot sort on unknown field: {}'.format(sort_field))

        return {'changed': False, 'snapshots': results}

    def tag_command(self):
        """
        Adds the given tag to all snapshots matching configured filters
        and properties

        Returns a module results dictionary with the following content:
        - 'changed': (bool) True if tags were updated on any snapshots
        - 'snapshots': (list) list of snapshots changed, if any
        """
        pass

    def run(self):
        command = self.params.get('command')
        cmd_call = '{}_command'.format(self.params.get('command', ''))

        if hasattr(self, cmd_call):
            return getattr(self, cmd_call)()
        else:
            self.module.fail_json(msg='Unknown cmd_call: {}'.format(command))


def create_tag_filter(key, value):
    """
    Given a key and a value, create a callable that returns true if the
    given snapshot contains this key and value in its tags.
    """
    def _filter_tag(snapshot):
        snap_tags = [frozenset(t.items()) for t in snapshot.get("Tags", [])]
        target = frozenset({"Key": key, "Value": value}.items())
        return target in snap_tags
    return _filter_tag


def create_numeric_field_filter(field_name, filter_call, field_type=float):
    """
    Return a callable that applies the given filter call against the value
    of the snapshot fact field, after it has been casted to a numeric type
    (float by default)
    """
    def _filter(snapshot):
        return filter_call(field_type(snapshot.get(field_name)))
    return _filter


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


def get_snapshot_facts(snapshots):
    return map(snapshot_as_fact, snapshots)


def snapshot_as_fact(snapshot):
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
        # assuming that if this is numerical, then it's seconds since epoch
        t = datetime.fromtimestamp(timestamp)

    return t.isoformat()


def main():
    argument_spec = ec2_argument_spec()

    argument_spec.update({
            'command':        dict(choices=['list', 'facts', 'tag', 'delete'],
                                   default='list', required=False),

            'cluster':        dict(aliases=['identifier',
                                            'instance'], required=False),

            'snapshot':       dict(required=False),

            'snapshot_type':  dict(required=False),

            'start_time':     dict(required=False),

            'end_time':       dict(required=False),

            'greater_than_mb': dict(type='float', required=False),

            'less_than_mb':   dict(type='float', required=False),

            'sort_by':        dict(required=False, default='create_time'),

            'tags':           dict(type='dict', required=False),
        })

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           mutually_exclusive=['cluster', 'snapshot'])

    rssmodule = RedshiftSnapshotsModule(module)
    result_dict = rssmodule.run()

    module.exit_json(**result_dict)


# import module snippets
from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.ec2 import *    # noqa


if __name__ == '__main__':
    main()
