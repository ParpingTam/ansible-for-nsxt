#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: nsxt_policy_group_associations_info
short_description: List policy groups associated with the specified object


version_added: "X.Y"
author: Ed McGuigan <ed.mcguigan@palmbeachschools.org>
options:
    hostname:
        description: Deployed NSX manager hostname.
        required: true
        type: str
    username:
        description: The username to authenticate with the NSX manager.
        required: true
        type: str
    password:
        description: The password to authenticate with the NSX manager.
        required: true
        type: str
    ca_path:
        description: Path to the CA bundle to be used to verify host's SSL
                     certificate
        type: str
    nsx_cert_path:
        description: Path to the certificate created for the Principal
                     Identity using which the CRUD operations should be
                     performed
        type: str
    nsx_key_path:
        description:
            - Path to the certificate key created for the Principal Identity
              using which the CRUD operations should be performed
            - Must be specified if nsx_cert_path is specified
        type: str        
        
    federation_role:
        description: Indicator of NSX Manager role within a federated deployment
        required: false
        type: string ( local|global )
        default: local
                   
    intent_path:
        description: All of these URLs are specific to a single group and an ID is needed
        required: true
        type: string
        
    enforcement_point_path:
        description: Required for some of the member types ( don't even understand it to be honest )
        required: false
        type: string
                
    page_size:
        description: if there is a desire to fetch the data in chunks rather than all at
                     once, an integer specifying the maximum number of objects to fetch
        required: false
        type: integer        
    cursor:
        description: when a page_size is specified, the returned data includes a "cursor" that
                     must be provided in a subsequent call in order to carry on where the prior call
                     left off. User would need to capture the cursor value from one call and provide it
                     in the next call
        required: false
        type: string        
    sort_ascending:
        description: Used to reverse sort order by setting it to False
        required: false
        type: bool
        default: True        
    sort_by:
        description: Field to sort on
        required: false
        type: string
        default: 
    include_mark_for_delete_objects:
        description: Show groups marked for deletion
        required: false
        type: bool
        default: False

'''
EXAMPLES = '''
  - name: Find referencing groups
    vmware.ansible_for_nsxt.nsxt_policy_group_associations_info:
      hostname: "{{ inventory_hostname }}"
      "username": "{{ username }}"
      "password": "{{ password }}"
      validate_certs: False
      federation_role: "{{ federation_role }}"
      intent_path: "{{ item.0 }}"
      enforcement_point_path: "{{ item.1 }}"
    register: group_associations
    delegate_to: 127.0.0.1
    loop: "{{ groups_wo_drs|product(enf_point_paths)|list }}"  
'''

RETURN = '''# '''
import json
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.policy_communicator import PolicyCommunicator
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.common_utils import build_url_query_dict, build_url_query_string, do_objects_get
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.nsxt_resource_urls import GLOBAL_POLICY_URL, LOCAL_POLICY_URL

from ansible.module_utils._text import to_native

def main():
    # Fetch the specification of the absolute basic arguments needed to connect to the NSX Manager
    argument_spec = PolicyCommunicator.get_vmware_argument_spec()
    # The URL will need to be specified as being non-global or global and we will need a domain
    URL_path_spec = dict(
        federation_role=dict(type='str', required=False, options=['local', 'global'], default='local')
        )
    URL_query_spec = dict(
                        cursor=dict(type='str', required=False ),
                        intent_path=dict(type='str', required=True ),
                        enforcement_point_path=dict(type='str', required=False ),
                        include_mark_for_delete_objects=dict(type='bool', required=False),
                        included_fields=dict(type='str', required=False),
                        page_size=dict(type='int'   , required=False ),
                        sort_ascending=dict(type='bool', required=False, default=True),
                        sort_by=dict(type='str', required=False)
                        )
    # Combine the base URL and URL path spec
    argument_spec.update(URL_path_spec)
    argument_spec.update(URL_query_spec)
    # Some code to validate the arguments provided with the invocation of the module
    # in a playbook versus the defined argument spec and to get the require AnsibleModule object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    if module.params['federation_role'] == 'global':
        url_path_root = GLOBAL_POLICY_URL
    else:
        url_path_root = LOCAL_POLICY_URL
    
    # Need to build up a query string
    url_query_string = build_url_query_string( build_url_query_dict(module.params, URL_query_spec.keys() ) )
    manager_url = 'https://{}{}/group-associations{}'.format(mgr_hostname,url_path_root,url_query_string)

    changed = False
    '''
    We potentially need to loop to fetch all data the code here will be the same for
    any object we are doing a GET on, not just Policy Groups, so I have put it into a function and put the function
    in the common_utils package.
    '''
    resp = do_objects_get(module,manager_url,module.params,
                        headers=dict(Accept='application/json'),validate_certs=validate_certs, ignore_errors=True)     

    module.exit_json(changed=changed, **resp)
if __name__ == '__main__':
    main()
