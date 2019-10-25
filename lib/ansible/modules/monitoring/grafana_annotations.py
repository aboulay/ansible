#!/usr/bin/python
# -*- coding: utf-8 -*-
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright: (c) 2019, Rémi REY (@rrey)

from __future__ import absolute_import, division, print_function

from ansible.module_utils.urls import fetch_url, basic_auth_header, url_argument_spec

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'metadata_version': '1.1'
}

DOCUMENTATION = '''
---
module: grafana_teams
author:
  - Rémi REY (@rrey)
version_added: "2.10"
short_description: Manage Grafana Teams
description:
  - Create/update/delete Grafana Teams through API.
options:
  url:
    description:
      - The Grafana URL.
    required: true
    type: str
  name:
    description:
      - The name of the Grafana Team.
    required: true
    type: str
  email:
    description:
      - The mail address associated with the Team.
    required: true
    type: str
  url_username:
    description:
      - The Grafana user for API authentication.
    default: admin
    type: str
    aliases: [ grafana_user ]
  url_password:
    description:
      - The Grafana password for API authentication.
    default: admin
    type: str
    aliases: [ grafana_password ]
  grafana_api_key:
    description:
      - The Grafana API key.
      - If set, C(url_username) and C(url_password) will be ignored.
    type: str
  members:
    description:
      - List of team members (emails).
      - The list can be enforced with C(enforce_members) parameter.
    type: list
  state:
    description:
      - Delete the members not found in the C(members) parameters from the
      - list of members found on the Team.
    default: present
    type: str
    choices: ["present", "absent"]
  enforce_members:
    description:
      - Delete the members not found in the C(members) parameters from the
      - list of members found on the Team.
    default: False
    type: bool
  use_proxy:
    description:
      - If C(no), it will not use a proxy, even if one is defined in an environment variable on the target hosts.
    type: bool
    default: yes
  client_cert:
    description:
      - PEM formatted certificate chain file to be used for SSL client authentication.
      - This file can also include the key as well, and if the key is included, I(client_key) is not required
    type: path
  client_key:
    description:
      - PEM formatted file that contains your private key to be used for SSL client authentication.
      - If I(client_cert) contains both the certificate and key, this option is not required.
    type: path
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated.
      - This should only set to C(no) used on personally controlled sites using self-signed certificates.
      - Prior to 1.9.2 the code defaulted to C(no).
    type: bool
    default: yes
'''

EXAMPLES = '''
---
- name: Create an annotation
  grafana_annotations:
      url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      dashboard_id: "grafana_working_group"
      panel_id: 1
      time: 1507037197339
      time_end: 1507180805056
      tags: ["tag1", "tag2"]
      text: "My annotation"
      state: present
'''

RETURN = '''
---
annotation:
    description: Information about the annotation.
    returned: On success
    type: complex
    contains:
        message:
            description: The Annotation message
            return always
            type: str
            sample:
                - "Annotation added"
        id:
            description: The ID of the created annotation
            returned: success
            type: int
            sample:
                - 1
'''

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, url_argument_spec, basic_auth_header
from ansible.module_utils.six.moves.urllib.parse import quote_plus

__metaclass__ = type

class GrafanaAnnotation(object):

    def __init__(self, text, time, tags=None, dashboard_id=None, panel_id=None, time_end=None, annotation_id=None):
        ## Mandatory
        self.text = text
        self.time = time
        ## Optionnal
        self.tags = tags
        self.dashboard_id = dashboard_id
        self.panel_id = panel_id
        self.time_end = time_end
        if time_end is None:
            self.time_end = time
        self.id = annotation_id

    def as_dict(self):
        return dict(text=self.text,
                    time=self.time,
                    tags=self.tags,
                    dashboard_id=self.dashboard_id,
                    panel_id=self.panel_id,
                    time_end=self.time_end,
                    id=self.id)

    def as_api_format(self):
        return dict(text=self.text,
                    time=self.time,
                    tags=self.tags,
                    dashboardId=self.dashboard_id,
                    panelId=self.panel_id,
                    timeEnd=self.time_end,
                    id=self.id)

    @property
    def json(self):
        return json.dumps(self.as_dict())



class GrafanaAnnotationService(object):

    def __init__(self, module):
        self._module = module
        # {{{ Authentication header
        self.headers = {"Content-Type": "application/json"}
        if module.params.get('grafana_api_key', None):
            self.headers["Authorization"] = "Bearer %s" % module.params['grafana_api_key']
        else:
            self.headers["Authorization"] = basic_auth_header(module.params['url_username'], module.params['url_password'])
        # }}}
        self.grafana_url = module.params.get("url")

    def create_annotation(self, annotation):
        url = "/api/annotations"
        response = self._send_request(url, data=annotation.as_api_format(), headers=self.headers, method="POST")
        return response

    def get_annotation(self, annotation):
        url = "/api/annotations?" + self._build_search_uri_params(annotation)
        response = self._send_request(url, headers=self.headers, method="GET")
        if len(response) > 1:
            raise AssertionError("Expected 1 annotation, got %d" % len(response))

        if len(response) == 0:
            return None
        return self._create_annotation_object(response[0])

    def delete_annotation(self, annotation):
      url = "/api/annotations/%d" % annotation.id
      response = self._send_request(url, headers=self.headers, method="DELETE")
      return response

    def _create_annotation_object(self, response):
        return GrafanaAnnotation(
          response["text"],
          response["time"],
          response["tags"],
          response["dashboardId"],
          response["panelId"],
          response["timeEnd"],
          response["id"]
        )

    def _build_search_uri_params(self, annotation):
        params = []
        annotation = annotation.as_dict()
        tags = annotation.get("tags", None)
        if tags:
            for tag in tags:
                params.append("tags=%s" % quote_plus(tag))
        if annotation.get("time", None):
            params.append("from=%s" % annotation.get("time"))
        if annotation.get("time_end", None):
            params.append("to=%s" % annotation.get("time_end"))
        if annotation.get("dashboard_id", None):
            params.append("dashboard_id=%s" % annotation.get("dashboard_id"))
        if annotation.get("panel_id", None):
            params.append("panel_id=%s" % annotation.get("panel_id"))

        params.append("type=annotation")

        if params:
            url_params = "%s" % '&'.join(params)
        return url_params

    def _send_request(self, url, data=None, headers=None, method="GET"):
        if data is not None:
            data = json.dumps(data, sort_keys=True)
        if not headers:
            headers = []

        full_url = "{grafana_url}{path}".format(grafana_url=self.grafana_url, path=url)
        resp, info = fetch_url(self._module, full_url, data=data, headers=headers, method=method)
        status_code = info["status"]
        if status_code == 404:
            return None
        elif status_code == 401:
            self._module.fail_json(failed=True, msg="Unauthorized to perform action '%s' on '%s' header: %s" % (method, full_url, self.headers))
        elif status_code == 403:
            self._module.fail_json(failed=True, msg="Permission Denied")
        elif status_code == 200:
            return self._module.from_json(resp.read())
        self._module.fail_json(failed=True, msg="Grafana Annotations API answered with HTTP %d" % status_code)


def setup_module_object():
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[['url_username', 'url_password']],
        mutually_exclusive=[['url_username', 'grafana_api_key']],
    )
    return module


argument_spec = url_argument_spec()
# remove unnecessary arguments
del argument_spec['force']
del argument_spec['force_basic_auth']
del argument_spec['http_agent']

argument_spec.update(
    time=dict(type='int', required=True),
    text=dict(type='str', required=True),
    state=dict(choices=['present', 'absent'], default='present'),
    dashboard_id=dict(type='int', required=False),
    panel_id=dict(type='int', required=False),
    time_end=dict(type='int', required=False),
    tags=dict(type='list', required=False),
    url=dict(type='str', required=True),
    grafana_api_key=dict(type='str', no_log=True),
    url_username=dict(aliases=['grafana_user'], default='admin'),
    url_password=dict(aliases=['grafana_password'], default='admin', no_log=True)
)


def main():

    module = setup_module_object()
    state = module.params['state']
    text = module.params['text']
    time = module.params['time']
    dashboard_id = module.params['dashboard_id']
    panel_id = module.params['panel_id']
    time_end = module.params['time_end']
    tags = module.params['tags']

    annotation_from_params = GrafanaAnnotation(text, time, tags, dashboard_id, panel_id, time_end)

    ####

    grafana_service = GrafanaAnnotationService(module)

    changed = False
    if state == 'present':
        annotation = grafana_service.get_annotation(annotation_from_params)
        if annotation is None: # create
            grafana_service.create_annotation(annotation_from_params)
            annotation = grafana_service.get_annotation(annotation_from_params)
            changed = True
        #if members is not None: # update
        #    cur_members = grafana_service.get_team_members(team.get("id"))
        #    plan = diff_members(members, cur_members)
        #    for member in plan.get("to_add"):
        #        grafana_service.add_team_member(team.get("id"), member)
        #        changed = True
        #    team = grafana_service.get_team(name)
        module.exit_json(failed=False, changed=changed, annotation=annotation.json)
    elif state == 'absent':
       annotation = grafana_service.get_annotation(annotation_from_params)
       if annotation is None:
           module.exit_json(failed=False, changed=False, message="No annotation found")
       result = grafana_service.delete_annotation(annotation)
       module.exit_json(failed=False, changed=True, message=result.get("message"))


#def diff_members(target, current):
#    diff = {"to_del": [], "to_add": []}
#    for member in target:
#        if member not in current:
#            diff["to_add"].append(member)
#    for member in current:
#        if member not in target:
#            diff["to_del"].append(member)
#    return diff


if __name__ == '__main__':
    main()
