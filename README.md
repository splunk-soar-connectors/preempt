[comment]: # "Auto-generated SOAR connector documentation"
# Preempt

Publisher: Splunk  
Connector Version: 2\.0\.4  
Product Vendor: Preempt  
Product Name: Preempt Platform  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app implements various incident management and investigative actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
The Preempt API Token can be found by logging into Preempt and navigating to your **Administration**
menu. Once in the Administration panel, navigate to **Connectors** . Under **API Keys** , you can
**Create Token** or select a token from the token list.

Valid values for the **type** parameter for the **get user activity** action are noted in Preempt
API documentation, found at **\<platform_address>/api-documentation/enum/TimelineEventType**


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Preempt Platform asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**platform\_address** |  required  | string | URL or IP of Preempt Platform
**api\_token** |  required  | password | API token
**first\_run\_max\_incidents** |  optional  | numeric | Maximum incidents to poll first time
**max\_incidents** |  optional  | numeric | Maximum incidents for scheduled polling
**verify\_server\_cert** |  optional  | boolean | Verify server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[on poll](#action-on-poll) - Ingest from Preempt  
[get user attributes](#action-get-user-attributes) - Gets the attributes of a user  
[get user risk](#action-get-user-risk) - Gets the risk of a user  
[watch user](#action-watch-user) - Watch a user  
[unwatch user](#action-unwatch-user) - Stop watching a user  
[get incident](#action-get-incident) - Get information about an incident  
[update incident](#action-update-incident) - Update the incident state and/or add a comment to the incident  
[get user activity](#action-get-user-activity) - Get user activity from the specified number of hours ago  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Ingest from Preempt

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Parameter ignored in this app | numeric | 
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_count** |  optional  | Maximum number of events to query for | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'get user attributes'
Gets the attributes of a user

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**attribute\_value** |  required  | Username or Attribute value to match\. If using secondaryDisplayName attribute, escape the backslash between domain and name | string |  `preempt user name` 
**attribute\_type** |  required  | Attribute name to match | string | 
**domain** |  required  | Domain of user | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attribute\_type | string | 
action\_result\.parameter\.attribute\_value | string |  `preempt user name` 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.emailAddresses | string |  `email` 
action\_result\.data\.\*\.entityId | string |  `preempt entity id` 
action\_result\.data\.\*\.isAdmin | boolean | 
action\_result\.data\.\*\.isHuman | boolean | 
action\_result\.data\.\*\.primaryDisplayName | string | 
action\_result\.data\.\*\.riskFactors\.\*\.type | string | 
action\_result\.data\.\*\.riskScore | numeric | 
action\_result\.data\.\*\.secondaryDisplayName | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.watched | boolean | 
action\_result\.summary\.primary\_display\_name | string | 
action\_result\.summary\.risk\_score | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get user risk'
Gets the risk of a user

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username or Attribute value to match | string |  `preempt user name` 
**domain** |  required  | Domain of user | string |  `domain`  `url` 
**attribute\_type** |  optional  | Attribute name to match | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.attribute\_type | string | 
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.parameter\.username | string |  `preempt user name` 
action\_result\.data\.\*\.riskFactors\.\*\.type | string | 
action\_result\.data\.\*\.riskScore | numeric | 
action\_result\.summary\.result | string | 
action\_result\.summary\.risk\_score | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'watch user'
Watch a user

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username or Attribute value to match | string |  `preempt user name` 
**domain** |  required  | Domain of user | string |  `domain`  `url` 
**attribute\_type** |  optional  | Attribute name to match | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.attribute\_type | string | 
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.parameter\.username | string |  `preempt user name` 
action\_result\.data\.\*\.updatedEntities\.\*\.primaryDisplayName | string | 
action\_result\.data\.\*\.updatedEntities\.\*\.secondaryDisplayName | string | 
action\_result\.summary\.result | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unwatch user'
Stop watching a user

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username or Attribute value to match | string |  `preempt user name` 
**domain** |  required  | Domain of user | string |  `domain`  `url` 
**attribute\_type** |  optional  | Attribute name to match | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.attribute\_type | string | 
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.parameter\.username | string |  `preempt user name` 
action\_result\.data\.\*\.updatedEntities\.\*\.primaryDisplayName | string | 
action\_result\.data\.\*\.updatedEntities\.\*\.secondaryDisplayName | string | 
action\_result\.summary\.result | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get incident'
Get information about an incident

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_number** |  required  | Incident number\. Example\: 5 for INC\-5 | numeric |  `preempt incident id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.incidentId | string | 
action\_result\.parameter\.incident\_number | numeric |  `preempt incident id` 
action\_result\.data\.\*\.alertEvents\.\*\.alertId | string | 
action\_result\.data\.\*\.alertEvents\.\*\.alertType | string | 
action\_result\.data\.\*\.alertEvents\.\*\.endTime | string | 
action\_result\.data\.\*\.alertEvents\.\*\.endpointEntity | string | 
action\_result\.data\.\*\.comments\.\*\.author\.displayName | string | 
action\_result\.data\.\*\.comments\.\*\.author\.type | string | 
action\_result\.data\.\*\.comments\.\*\.author\.username | string | 
action\_result\.data\.\*\.comments\.\*\.text | string | 
action\_result\.data\.\*\.comments\.\*\.timestamp | string | 
action\_result\.data\.\*\.compromisedEntities\.\*\.accounts\.\*\.archived | boolean | 
action\_result\.data\.\*\.compromisedEntities\.\*\.accounts\.\*\.dataSource | string | 
action\_result\.data\.\*\.compromisedEntities\.\*\.accounts\.\*\.enabled | boolean | 
action\_result\.data\.\*\.endTime | string | 
action\_result\.data\.\*\.lifeCycleStage | string | 
action\_result\.data\.\*\.markedAsRead | boolean | 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.startTime | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.severity | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update incident'
Update the incident state and/or add a comment to the incident

Type: **generic**  
Read only: **False**

An incident's stage cannot be changed from "resolved" to another stage\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_number** |  required  | Incident number\. Example\: 5 for INC\-5 | numeric |  `preempt incident id` 
**stage** |  optional  | Life cycle stage to update incident to | string | 
**reason** |  optional  | Reason for updating incident\. This parameter is required if updating stage | string | 
**comment** |  optional  | Comment to add to incident | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.incident\_number | numeric |  `preempt incident id` 
action\_result\.parameter\.reason | string | 
action\_result\.parameter\.stage | string | 
action\_result\.data\.\*\.addCommentToIncident\.incident\.comments\.\*\.author\.displayName | string | 
action\_result\.data\.\*\.addCommentToIncident\.incident\.comments\.\*\.text | string | 
action\_result\.data\.\*\.setIncidentState\.incident\.lifeCycleStage | string | 
action\_result\.summary\.comment\_status | string | 
action\_result\.summary\.life\_cycle\_state | string | 
action\_result\.summary\.num\_comments | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get user activity'
Get user activity from the specified number of hours ago

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username to get activity of | string |  `preempt user name` 
**start\_time** |  required  | Starting time of search in ISO\-8601 date string format \(YYYY\-MM\-DD\)\. Examples\: 2019\-12\-12, P\-1W | string | 
**types** |  optional  | Comma separated list of types of events to return\. All types of events returned if left blank | string | 
**limit** |  optional  | Number of results to return, or leave field blank to return all results | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.start\_time | string | 
action\_result\.parameter\.types | string | 
action\_result\.parameter\.username | string |  `preempt user name` 
action\_result\.data\.\*\.authenticationType | string | 
action\_result\.data\.\*\.endpointEntity | string | 
action\_result\.data\.\*\.eventLabel | string | 
action\_result\.data\.\*\.eventSeverity | string | 
action\_result\.data\.\*\.eventType | string | 
action\_result\.data\.\*\.hostName | string |  `host name` 
action\_result\.data\.\*\.ipAddress | string |  `ip` 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.data\.\*\.userEntity\.primaryDisplayName | string | 
action\_result\.data\.\*\.userEntity\.secondaryDisplayName | string | 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 