#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2018 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import (absolute_import, division, print_function)
from pickle import FALSE
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_policy_group
short_description: Create or Delete a Policy Policy Group
description:
    Creates or deletes a Policy Policy Group.
    Required attributes include id and display_name.
version_added: "2.8"
author: Gautam Verma
extends_documentation_fragment:
    - vmware.ansible_for_nsxt.vmware_nsxt
options:
    id:
        description: The id of the Policy Policy Group.
        required: false
        type: str
    description:
        description: Policy Group description.
        type: str
    domain_id:
        description: Domain ID.
        type: str
    expression:
        description:
            - The expression list must follow below criteria
                - 1. A non-empty expression list, must be of odd size.
                  In a list, with indices starting from 0, all
                  non-conjunction expressions must be at
                  even indices, separated by a conjunction expression
                  at odd indices.
                - 2. The total of ConditionExpression and
                  NestedExpression in a list should not exceed 5.
                - 3. The total of IPAddressExpression,
                  MACAddressExpression, external IDs in an
                  ExternalIDExpression and paths in a PathExpression
                  must not exceed 500.
                - 4. Each expression must be a valid Expression. See
                  the definition of the Expression type for more
                  information.
        type: list
    extended_expression:
        description:
            - Extended Expression allows additional higher level context to be
              specified for grouping criteria (e.g. user AD group). This field
              allow users to specified user context as the source of a firewall
              rule for IDFW feature.  Current version only support a single
              IdentityGroupExpression. In the future, this might expand to
              support other conjunction and non-conjunction expression.
            - The extended expression list must follow below criteria
                - 1. Contains a single IdentityGroupExpression. No conjunction
                  expression is supported
                - 2. No other non-conjunction expression is supported, except
                  for IdentityGroupExpression
                - 3. Each expression must be a valid Expression. See the
                  definition of the Expression type for more information
                - 4. Extended expression are implicitly AND with expression
                - 5. No nesting can be supported if this value is used
                - 6. If a Group is using extended expression, this group must
                  be the only member in the source field of an communication
                  map
        type: list
    group_state:
        description: Realization state of this group
        type: str
        choices:
            - IN_PROGRESS
            - SUCCESS
            - FAILURE
'''

EXAMPLES = '''
- name: create Policy Group
  nsxt_policy_group:
    hostname: "10.10.10.10"
    nsx_cert_path: /root/com.vmware.nsx.ncp/nsx.crt
    nsx_key_path: /root/com.vmware.nsx.ncp/nsx.key
    validate_certs: False
    id: test-lb-service
    display_name: test-lb-service
    state: "present"
    domain_id: "default"
    expression:
      - member_type: "VirtualMachine"
        value: "webvm"
        key: "Tag"
        operator: "EQUALS"
        resource_type: "Condition"
'''

RETURN = '''# '''

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_base_resource import NSXTBaseRealizableResource
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_resource_urls import POLICY_GROUP_URL
from ansible.module_utils._text import to_native


def _lists_equal(list1, list2):
    # Returns True if list1 and list2 are equal
    try:
        # If the lists can be converted into sets, do so and
        # compare lists as sets.
        set1 = set(list1)
        set2 = set(list2)
        return set1 == set2
    except Exception:
        return False 

def _matchfound(expression_element, existing_expression):
    resource_type = expression_element['resource_type']
    match_found = False
    for existing_ee in existing_expression:
        # We can bypass if the resource_type is not the same
        if resource_type != existing_ee['resource_type']:
            continue
        # So resource_type is the same so a match is possible
        # We can have more than one element of a given resource_type
        # such as a Condition or a ConjunctionOperator
        missing_key = False
        differing_value = False
        for (k,v) in expression_element.items():
            if k not in existing_ee.keys():
                missing_key = True
                # Need to continue the outer loop
                break
            # key was found so values can be compared
            elif v != existing_ee[k]:
                # If the values don't match but they are a list
                # as is the case with paths, ip_addresses, external_ids
                # the lists need to be properly checked for equality
                if type(v).__name__ == 'list':
                    if not _lists_equal(v, existing_ee[k]):
                        # Move to next element of existing expressions
                        differing_value = True
                        break
                else:
                    differing_value = True
                    break
        if missing_key or differing_value:
            # Check next expression element in existing expression
            continue
        # If we get down to here the existing_ee must have matched
        return True
    return False
                

def _expressions_equal(resource_expression, existing_expression):
    '''
    Only certain fields must be compared, others need to be ignored.
    We need to throw an error if a key is found that is not known.
    '''
    allowed_fields = set(('resource_type',
                          'value', 
                          'operator', 
                          'key', 
                          'member_type', 
                          'conjunction_operator',
                          'mac_addresses',
                          'ip_addresses',
                          'paths',
                          'external_ids'
                          ))
    other_known_fields = set((
                                'id',
                                'path',
                                'relative_path',
                                'parent_path',
                                'marked_for_delete',
                                'overridden',
                                '_protection'
                            ))
    all_known_fields = allowed_fields | other_known_fields
    # If there is a length difference then we know they aren't the same
    if len(resource_expression) != len(existing_expression):
        return False
    # Suppress other_known_fields from existing_expression elements
    for expression_element in existing_expression:
        for key in other_known_fields:
            if key in expression_element.keys():
                expression_element.pop(key)
        unknown_keys = [ key for key in expression_element.keys() 
                            if key not in allowed_fields ]
        if unknown_keys:
            # We have a key that isn't accounted for so we
            # can't do a proper equality check
            return False
    # now for each element in the resource_expression we need to look
    # for an equal element in the existing_expression
    for expression_element in resource_expression:
        if not _matchfound(expression_element, existing_expression):
            return False
    return True
        


class NSXTPolicyGroup(NSXTBaseRealizableResource):
    @staticmethod
    def get_resource_spec():
        policy_group_arg_spec = {}
        policy_group_arg_spec.update(
            domain_id=dict(
                required=True,
                type='str'
            ),
            expression=dict(
                required=True,
                type='list'
            ),
            extended_expression=dict(
                required=False,
                type='list'
            ),
            group_state=dict(
                required=False,
                type='str'
            ),
        )
        return policy_group_arg_spec

    @staticmethod
    def get_resource_base_url(baseline_args,federation_role='local'):
        local_url = POLICY_GROUP_URL.format(baseline_args["domain_id"])
        if federation_role == 'global':
            # replace /infra with /global-infra
            return "/global-{}".format(local_url[1:])
        else:
            return local_url

    def update_resource_params(self, nsx_resource_params):
        # Parameters that were provided but that should not be included
        # in the JSON sent to the NSX manager.
        #
        # The domain string is used in the URL but not in the JSON so it is removed
        nsx_resource_params.pop('domain_id')
    

        
    def check_for_update(self, existing_params, resource_params):
        """
            Method in NSXTBaseRealizableResource returns True because
            it detects changes in expression elements so a custom
            method is needed for  Policy Group resource
        """
        if not existing_params:
            return False
        for k, v in resource_params.items():
            if k not in existing_params:
                return True
            elif type(v).__name__ == 'dict':
                # Recursive call to same method
                if self.check_for_update(existing_params[k], v):
                    return True
            # If there is a difference in the values
            elif v != existing_params[k]:
                # If the value is a list then let's perform a list comparison
                if type(v).__name__ == 'list':
                    # Need some custom code for the 'expression' value
                    if k == 'expression':
                        if not _expressions_equal(v, existing_params[k]):
                            return True
                    elif _lists_equal(v, existing_params[k]):
                            return True
                    continue
                # If the value is not a list then a different value means an object update
                return True
        return False


if __name__ == '__main__':
    policy_group = NSXTPolicyGroup()
    policy_group.realize(baseline_arg_names=["domain_id"])
