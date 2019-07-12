# File: preempt_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from preempt_consts import *
import requests
import json
from bs4 import BeautifulSoup

import time
import datetime

class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class PreemptConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(PreemptConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self.platform_address = None
        self.api_token = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, method="post", data=None, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self.platform_address + '/api/public/graphql'

        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {}'.format(self.api_token)
        }

        try:
            r = request_func(
                            url,
                            headers=headers,
                            json={'query': data},
                            verify=config.get('verify_server_cert', False),
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Retrieving Administrator Role entity")

        data = '''{
            entities(
            roles: [BuiltinAdministratorRole],first: 1){
                nodes {
                primaryDisplayName
                secondaryDisplayName
                }
            }
        }'''

        # make rest call
        ret_val, response = self._make_rest_call(action_result, data=data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_user_attributes(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param['username']
        attribute = param['attribute']
        domain = param['domain']

        attribute_type = ATTRIBUTE_TYPES.get(attribute)

        data = '''{{
            entities({attribute_type}: "{username}"
                    domains: "{domain}"
                    archived: false
                    first: 1)
            {{
                nodes {{
                    entityId
                    type

                    primaryDisplayName
                    secondaryDisplayName

                    isHuman: hasRole(type: HumanUserAccountRole)
                    isAdmin: hasRole(type: AdminAccountRole)

                    riskScore
                    riskFactors
                    {{
                        type
                    }}

                    ... on UserEntity 
                    {{
                        emailAddresses
                        phoneNumbers
                        watched
                    }}

                    ownedEndpoints: associations(bindingTypes: OWNERSHIP)
                    {{
                        ... on EntityAssociation
                        {{
                        entity
                        {{
                            primaryDisplayName
                            secondaryDisplayName
                        }}
                        }}
                    }}
                }}
            }}
        }}'''.format(attribute_type=attribute_type, username=username, domain=domain)

        # make rest call
        ret_val, response = self._make_rest_call(action_result, data=data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        result = response.get('data', {}).get('entities', {}).get('nodes', [])

        summary = action_result.update_summary({})

        if len(result) > 0:
            action_result.add_data(result[0])
            summary['risk_score'] = result[0].get('riskScore')
            summary['primary_display_name'] = result[0].get('primaryDisplayName')
        else:
            action_result.add_data({ 'riskScore': 'Unavailable' })
            action_result.add_data({ 'primaryDisplayName': 'Unavailable' })
            summary['result'] = "Username and domain combination not found"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_user_risk(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param['username']
        domain = param['domain']

        data = '''{{
            entities(samAccountNames: "{username}"
                    domains: "{domain}"
                    archived: false
                    first: 1)
            {{
                nodes {{
                    riskScore
                    riskFactors
                    {{
                        type
                    }}
                }}
            }}
        }}'''.format(username=username, domain=domain)

        # make rest call
        ret_val, response = self._make_rest_call(action_result, data=data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        result = response.get('data', {}).get('entities', {}).get('nodes', [])

        summary = action_result.update_summary({})

        if len(result) > 0:
            action_result.add_data(result[0])
            summary['risk_score'] = result[0].get('riskScore')
        else:
            action_result.add_data({ 'riskScore': 'Unavailable' })
            summary['result'] = "Username and domain combination not found"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_watch_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param['username']
        domain = param['domain']

        data = '''mutation {{
            addEntitiesToWatchList(input: {{ entityQuery: {{ samAccountNames: "{username}", domains: "{domain}" }} }})
            {{
                updatedEntities
                {{
                primaryDisplayName
                secondaryDisplayName
                }}
            }}
        }}'''.format(username=username, domain=domain)

        # make rest call
        ret_val, response = self._make_rest_call(action_result, data=data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        result = response.get('data', {}).get('addEntitiesToWatchList', {})
        action_result.add_data(result)

        summary = action_result.update_summary({})
        if len(result.get('updatedEntities', [])) == 0:
            summary['result'] = "No entities updated"
        else:
            summary['result'] = "{} was added to the watch list".format(result['updatedEntities'][0]['primaryDisplayName'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unwatch_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param['username']
        domain = param['domain']

        data = '''mutation {{
            removeEntitiesFromWatchList(input: {{ entityQuery: {{ samAccountNames: "{username}", domains: "{domain}" }} }})
            {{
                updatedEntities
                {{
                primaryDisplayName
                secondaryDisplayName
                }}
            }}
        }}'''.format(username=username, domain=domain)

        # make rest call
        ret_val, response = self._make_rest_call(action_result, data=data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        result = response.get('data', {}).get('removeEntitiesFromWatchList', {})
        action_result.add_data(result)

        summary = action_result.update_summary({})
        if len(result.get('updatedEntities', [])) == 0:
            summary['result'] = "No entities updated"
        else:
            summary['result'] = "{} was removed from the watch list".format(result['updatedEntities'][0]['primaryDisplayName'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_incident(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = param['incident_id']
        stage = param['stage']
        reason = param['reason']

        data = '''mutation {{
            setIncidentState(input: {{ incidentId: "{incident_id}", lifeCycleStage: {stage}, reason: "{reason}" }})
            {{
                incident
                {{
                lifeCycleStage
                }}
            }}
        }}'''.format(incident_id=incident_id, stage=stage, reason=reason)

        # make rest call
        ret_val, response = self._make_rest_call(action_result, data=data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_user_activity(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = param['incident_id']
        stage = param['stage']
        reason = param['reason']

        data = '''mutation {{
            setIncidentState(input: {{ incidentId: "{incident_id}", lifeCycleStage: {stage}, reason: "{reason}" }})
            {{
                incident
                {{
                lifeCycleStage
                }}
            }}
        }}'''.format(incident_id=incident_id, stage=stage, reason=reason)

        # make rest call
        ret_val, response = self._make_rest_call(action_result, data=data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):
        
        self.save_progress("Connecting to {}".format(self.platform_address))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get time from last poll, save now as time for this poll
        last_time = self._state.get('last_time', 0)
        self._state['last_time'] = time.time()

        data = '''{{
            incidents(after: {after}
                        sortOrder: DESCENDING
                        sortKey: END_TIME
                        first: 5) {{
                nodes {{
                type
                startTime
                endTime
                compromisedEntities {{
                    type
                    primaryDisplayName
                    secondaryDisplayName
                }}
                alertEvents {{
                    eventLabel
                    entities {{
                    type
                    primaryDisplayName
                    secondaryDisplayName
                    }}
                }}
                }}
                pageInfo
                {{}}
                endCursor
                }}
            }}
        }}'''

        # If it's a poll now don't filter based on update time
        if self.is_poll_now():
            max_incidents = param.get(phantom.APP_JSON_CONTAINER_COUNT)

        # If it's the first poll, don't filter based on update time
        elif (self._state.get('first_run', True)):
            self._state['first_run'] = False
            max_incidents = int(config.get('first_run_max_tickets', -1))

        # If it's scheduled polling add a filter for update time being greater than the last poll time
        else:
            max_incidents = int(config.get('max_incidents', -1))
            query = '{0}{1}updated>="{2}"'.format(query, ' and ' if query else '', datetime.fromtimestamp(last_time).strftime(JIRA_TIME_FORMAT))

        # Make rest call using query
        ret_val, response = self._make_rest_call(action_result, data=data)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_user_attributes':
            ret_val = self._handle_get_user_attributes(param)

        elif action_id == 'get_user_risk':
            ret_val = self._handle_get_user_risk(param)

        elif action_id == 'watch_user':
            ret_val = self._handle_watch_user(param)

        elif action_id == 'unwatch_user':
            ret_val = self._handle_unwatch_user(param)

        elif action_id == 'update_incident':
            ret_val = self._handle_update_incident(param)

        elif action_id == 'on_poll':
            ret_val = self._on_poll(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self.platform_address = config['platform_address'].rstrip('/')
        self.api_token = config['api_token']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = PreemptConnector._get_phantom_base_url() + '/login'

            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PreemptConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
