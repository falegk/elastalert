# -*- coding: utf-8 -*-
import json
import types
import elastalert
import os
import re

from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from elastalert.util import elastalert_logger, pretty_ts, ts_to_dt

from elastalert.util import elasticsearch_client
from elastalert.util import lookup_es_key
from elastalert.util import EAException
from elastalert.util import hashable

from elastalert.alerts import Alerter, BasicMatchString
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ElasticsearchException
from elasticsearch.exceptions import ConnectionError
from elasticsearch.exceptions import TransportError

from email.mime.text import MIMEText
from email.utils import formatdate, COMMASPACE
from email.mime.multipart import MIMEMultipart

from smtplib import SMTP
from smtplib import SMTP_SSL
from smtplib import SMTPAuthenticationError
from smtplib import SMTPException
from socket import error


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)

#--- Helpers ----------------------------------------------
def _convert_to_strings(list_of_strs):
    if isinstance(list_of_strs, (list, tuple)):
        result = COMMASPACE.join(list_of_strs)
    else:
        result = list_of_strs
    return str(result)

def _encode_str(s):
    if type(s) == types.UnicodeType:
        return s.encode('utf8')
    return s

# Returns True/False if an incident already exists
# Searches for:
#   - name
#   - status [Escalated || Incident Response]
#   - correlated_values [Same key & value]
def _incident_exists(self, rule):
    # Search if the incident exists
    q = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"incident_name.keyword": self.incident_attr['incident_name'] }}
                ],
                "should": [
                    {"term": { "status.keyword": "Escalated" }},
                    {"term": { "status.keyword": "Uber Escalated" }},
                    {"term": { "status.keyword": "Incident Response" }}
                ],
                "minimum_should_match": 1
            }
        }
    }

    if len(self.correlated_values) > 0:
        cv = self.correlated_values[0]
        value = cv['value'] if cv['value'] is not None else ' '
        q['query']['bool']['must'].append({"term": {"correlated_values.value.keyword": value.replace("\\", "\\\\") }})
        q['query']['bool']['must'].append({"term": {"correlated_values.qk.keyword": cv['qk'] }})

    incident = self.es_client.count(index=rule['incident_index'], doc_type=self.incident_attr['doc_type'], body=q)
    return incident['count'] > 0

def _uber_incident_exists(self, rule):
    # Search if the incident exists
    q = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"incident_name.keyword": self.incident_attr['incident_name'] }}
                ],
                "must_not": [
                    {"term": { "status.keyword": "Resolved" }}
                ]
            }
        }
    }

    if len(self.correlated_values) > 0:
        cv = self.correlated_values[0]
        value = cv['value'] if cv['value'] is not None else ' '
        q['query']['bool']['must'].append({"term": {"correlated_values.value.keyword": value.replace("\\", "\\\\") }})
        q['query']['bool']['must'].append({"term": {"correlated_values.qk.keyword": cv['qk'] }})

    incident = self.es_client.count(index=rule['incident_index'], doc_type=self.incident_attr['doc_type'], body=q)
    return incident['count'] > 0

def _uber_incident_name(self):
    value = self.correlated_values[0].get('value', '?')
    timeframe = ("%d hours" % (_timedelta_to_hours(self.rule['timeframe']))) if self.rule['timeframe'] else ''
    return "Multiple Incidents occurring for %s within %s" % (value, timeframe)

def _timedelta_to_hours(td):
    seconds = td.total_seconds()
    # days, seconds = td.days, td.seconds
    return seconds // 3600


# Supports:
#   email*
#   email_reply_to
#   num_events
#   smtp_host
#   smtp_port
#   smtp_ssl
#   smtp_auth_file
#   from_addr
#   template_text_content
#   template_text_file
#   template_html_content
#   template_html_file
#
# (* required)

class CloneEmail(Alerter):
    """ Sends an email alert """
    required_options = frozenset(['email'])

    def __init__(self, *args):
        super(CloneEmail, self).__init__(*args)
        self.uber_incident = self.rule.get('uber_incident', False)

        self.incident_attr = self.rule['incident_attributes']
        self.smtp_host = self.rule.get('smtp_host', 'localhost')
        self.smtp_ssl = self.rule.get('smtp_ssl', False)
        self.from_addr = self.rule.get('from_addr', 'ElastAlert')
        self.smtp_port = self.rule.get('smtp_port')
        if self.rule.get('smtp_auth_file'):
            self.get_account(self.rule['smtp_auth_file'])
        # Convert email to a list if it isn't already
        if isinstance(self.rule['email'], str):
            self.rule['email'] = [self.rule['email']]
        self.app_type = 'uber_incident' if self.uber_incident else self.rule.get('app_type', 'siem')
        self.event_fields = self.rule.get('event_fields', None)
        self.es_fields = []

    def alert(self, matches):
        self.es_client = elasticsearch_client(self.rule)

        self.all_matches = matches[0].get('related_events', [])
        self.correlated_values = matches[0].get('correlated_values', [])
        self.important_list = matches[0].get('important_fields_list', [])
        self.additional_results = matches[0].get('additional_results', {})
        self.num_hits = matches[0].get('num_hits', 0)

        if self.uber_incident:
            if _uber_incident_exists(self, self.rule):
                elastalert_logger.info("CloneEmail: An Uber incident with name [%(incident_name)s] and status [Uber Escalated] already exists"
                                       % {"incident_name": self.incident_attr['incident_name']})
                return
        else:
            if _incident_exists(self, self.rule):
                elastalert_logger.info("CloneEmail: An incident with name [%(incident_name)s] and status [Escalated || Incident Response] already exists"
                                       % {"incident_name": self.incident_attr['incident_name']})
                return

        # Set Email Subject
        if self.uber_incident:
            subject = _uber_incident_name(self)

            for event in self.all_matches:
                event['events'] = []
                if event.get("events_added_count", 0) > 0:
                    try:
                        body = { "query": { "match": { "incident_id": event["_id"] }}}
                        resp = self.es_client.search(index=self.rule['events_index'], body=body, size=1)
                        hits = resp['hits']['hits']
                    except ElasticsearchException as e:
                        event['events'].append({"id": "0", "message": "Not Found"})
                        elastalert_logger.error("Error querying for incident's events: %s" % e)

                    if hits:
                        event['events'].append({"id": hits[0]["_id"], "message": hits[0]["_source"].get("syslog_message", "Not Found")})
                    else:
                        event['events'].append({"id": "0", "message": "Not Found"})
        else:
            subject = str(self.create_title(matches))

        if 'template_text_content' in self.rule:
            text = self.rule['template_text_content']
        elif 'template_text_file' in self.rule:
            with open(self.rule['template_text_file'], 'r') as f:
                text = f.read()
        else:
            text = '{{ matches|length }} items found'

        if 'template_html_content' in self.rule:
            html = self.rule['template_html_content']
        elif 'template_html_file' in self.rule:
            with open(self.rule['template_html_file'], 'r') as f:
                html = f.read()
        else:
            # Default template: modules-dir/email_templates/siem_template.html
            def_dir_path = os.path.dirname(os.path.realpath(__file__))
            with open(def_dir_path+"/email_templates/"+self.app_type+"_template.html", 'r') as f:
                html = f.read()

        env = {
            'rule': self.rule,
            'rule_name': self.rule['name'],
            'matches': self.all_matches,
            'correlated_values': self.correlated_values,
            'important_list': self.important_list,
            'additional_results': self.additional_results,
            'pipeline': self.pipeline,
            'json': json,
            'datetime': datetime,
            'email_table_title': self.rule.get('email_table_title', 'Logs'),
            'num_hits': self.correlated_values[0]['counts'] if (len(self.correlated_values) > 0) else self.num_hits
        }

        # Generate dynamically events table fields
        if self.app_type == 'ips':
            if self.event_fields and len(self.event_fields) == 5:
                t_columns = ['Timestamp', 'Source/Destination', self.event_fields[2], self.event_fields[3], self.event_fields[4]]
                self.es_fields = self.generate_email_fields()
            else:
                t_columns = ['Timestamp', 'Source/Destination', 'Signature', 'Source Country', 'Priority']
                self.es_fields = self.generate_email_fields(defaults=True)
            env.update({'t_columns': t_columns, 'es_fields': self.es_fields})

        text = Environment().from_string(text).render(**env)
        html = Environment().from_string(html).render(**env)

        messageRoot = MIMEMultipart('related')
        messageRoot['Subject'] = subject
        messageRoot['From']    = str(self.from_addr)
        messageRoot['To']      = _convert_to_strings(self.rule['email'])

        if self.rule.get('email_reply_to'):
            messageRoot['Reply-To'] = _convert_to_strings(self.rule.get('email_reply_to'))

        messageRoot.preamble = 'This is a multi-part message in MIME format.'

        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgAlternative.attach(MIMEText(str(text), 'plain'))
        msgAlternative.attach(MIMEText(str(html), 'html'))
        messageRoot.attach(msgAlternative)

        try:
            if self.smtp_ssl:
                if self.smtp_port:
                    self.smtp = SMTP_SSL(self.smtp_host, self.smtp_port)
                else:
                    self.smtp = SMTP_SSL(self.smtp_host)
            else:
                if self.smtp_port:
                    self.smtp = SMTP(self.smtp_host, self.smtp_port)
                else:
                    self.smtp = SMTP(self.smtp_host)
                self.smtp.ehlo()
                if self.smtp.has_extn('STARTTLS'):
                    self.smtp.starttls()
            if 'smtp_auth_file' in self.rule:
                self.smtp.login(self.user, self.password)
        except (SMTPException, error) as e:
            raise EAException("Error connecting to SMTP host: %s" % (e))
        except SMTPAuthenticationError as e:
            raise EAException("SMTP username/password rejected: %s" % (e))

        # Display email message in logs
        elastalert_logger.info("EMAIL Message \n\n %s" % messageRoot.as_string())

        self.smtp.sendmail(messageRoot['From'], self.rule['email'], messageRoot.as_string())
        self.smtp.close()

        elastalert_logger.info("Sent email to %s for rule: %s" % (self.rule['email'], self.rule['name']))

    def create_default_title(self, matches):
        self.all_matches = matches[0].get('related_events', [])
        self.num_hits = matches[0].get('num_hits', 0)

        subject = '%s: %d matches found - %s' % \
                  (self.rule['name'], self.num_hits,
                   pretty_ts(ts_to_dt(self.pipeline['alert_time'])))

        return subject

    def create_custom_title(self, matches):
        # Assume rule['alert_subject'] to be a jinja templated string. See Alerter.create_title()
        subject = self.rule['alert_subject']

        es_conn_conf = elastalert.ElastAlerter.build_es_conn_config(self.rule)
        env = {
            'rule': self.rule,
            'matches': matches,
            'pipeline': self.pipeline,
            'jira_server': self.pipeline['jira_server'] if (self.pipeline and 'jira_server' in self.pipeline) else None,
            'jira_ticket': self.pipeline['jira_ticket'] if (self.pipeline and 'jira_ticket' in self.pipeline) else None,
            'datetime': datetime,
        }

        return Environment().from_string(subject).render(**env)

    def get_info(self):
        return {'type': 'clone-email',
                'recipients': self.rule['email']}

    # Returns an array of string or lists
    # an element must be array if is nested es field
    # Example: alert.signature => ['alert', 'signature']
    def generate_email_fields(self, defaults=False):
        if defaults:
            fields = ['@timestamp', 'src_ip', ['alert', 'signature'], ['src_geoip', 'country_name'], ['alert', 'severity']]
        else:
            f3 = self.event_fields[2].split(".")
            f4 = self.event_fields[3].split(".")
            f5 = self.event_fields[4].split(".")
            fields = ['@timestamp', 'src_ip', f3, f4, f5]

        return fields


class CreateIncident(Alerter):
    """ Stores incidents & incident_alerts to ElasticSearch

    :param incident_attributes: Includes all incident attributes
    :param event_attributes: Includes all extra event attributes
    :param incident_index: Incidents index name
    :param events_index: Incident Events index name
    """
    required_options = frozenset([
        'incident_index',
        'events_index',
        'incident_attributes',
        'event_attributes'
    ])

    def __init__(self, rule):
        super(CreateIncident, self).__init__(rule)
        self.uber_incident = self.rule.get('uber_incident', False)
        self.es_client = elasticsearch_client(self.rule)

        self.query_filter = self.rule['filter']
        self.incident_attr = self.rule['incident_attributes']
        self.event_attr = self.rule['event_attributes']
        self.related_events = None
        self.correlated_values = []
        self.incident_id = ''
        self.out_put_file = self.rule.get('output_file_path', None)
        self.important_fields = self.rule.get('important_fields_list', [])
        self.important_list = []
        self.incident_events = []
        self.incident_tuple = []
        self.additional_results = {}

    def alert(self, matches):
        for match in matches:
            self.related_events = match.get('related_events', [])
            self.correlated_values = match.get('correlated_values', [])
            self.important_list = match.get('important_fields_list', [])
            self.additional_results = match.get('additional_results', {})

        # Checks if an incident must be opened or not
        if self.uber_incident:
            if _uber_incident_exists(self, self.rule):
                elastalert_logger.info("CreateIncident: An Uber incident with name [%(incident_name)s] and status [Uber Escalated] already exists"
                                       % {"incident_name": self.incident_attr['incident_name']})
                return
        else:
            if _incident_exists(self, self.rule):
                elastalert_logger.info("CreateIncident: An incident with name [%(incident_name)s] and status [Escalated || Incident Response] already exists"
                                       % {"incident_name": self.incident_attr['incident_name']})
                return

        if self.uber_incident:
            # Keeps a list with incident ids
            self.incident_tuple = map(lambda incident:
                                      { "id": str(incident.get('_id', '')),
                                        "name": str(incident.get('incident_name', ''))}, self.related_events[:99])

        # top_count_keys can be used for rules with aggregations
        # top_count_keys:
        #   - correlated_values.value
        #   - status
        # if 'top_count_keys' in self.rule:
        #     for key in self.rule.get('top_count_keys', []):
        #         self.top_events.append(matches[0]['top_events_%s' % key])

        # Matches is a list of match dictionaries.
        # It contains more than one match when the alert has
        # the aggregation option set
        # ONLY FOR TESTING
        # json_payload = json.dumps(self.related_events, cls=DateTimeEncoder, indent=4)
        # with open("alerts.json", "a") as output_file:
        #     output_file.write(json_payload)
        incident_name = _uber_incident_name(self) if self.uber_incident else self.incident_attr['incident_name']
        incident_query = {
            "uber_incident": self.uber_incident,
            "user_id": self.incident_attr['user_id'],
            "@timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            "incident_name": incident_name,
            "incident_description": self.incident_attr['incident_description'],
            "alert_id": self.incident_attr.get('alert_id', None), # Alert from our db
            "search_id": self.incident_attr.get('search_id', None), # Search from our db
            "priority": self.incident_attr['incident_priority'],
            "priority_code": self.incident_attr['incident_priority_code'],
            "status": self.incident_attr['incident_status'],
            "category": self.incident_attr['incident_category'],
            "operating_system": self.incident_attr['operating_system'],
            "security_layer": self.incident_attr['security_layer'],
            "auto_close": self.incident_attr['auto_close'],
            "soc_investigation": self.incident_attr['soc_investigation'],
            "events_added_count": len(self.related_events),
            "created_at": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            "updated_at": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            "correlated_values": self.correlated_values,
            "important_fields_list": self.important_list,
            "incidents": self.incident_tuple

        }
        if self.uber_incident:
            incident_query["incident_alert_id"] = self.incident_attr.get('incident_alert_id', '')

        # Creates a new incident
        resp = self.es_client.index(index=self.rule['incident_index'], doc_type=self.incident_attr['doc_type'],
                                    body=incident_query, params={'refresh': 'true'})
        self.incident_id = resp['_id']
        elastalert_logger.info("[%(index)s] Create Incident: %(created)s ID: %(id)s"
                               % {"index": resp['_index'], "created": resp['result'] == 'created',
                                  "id": self.incident_id})

        if self.uber_incident:
            self.store_incidents_to_es()
        else:
            self.store_events_to_es()

        self.incident_events = []
        self.incident_tuple = []
        if 'additional_results' in matches[0]:
            matches[0]['additional_results'] = []
        self.additional_results = []

    # get_info is called after an alert is sent to get data that is written back
    # to Elasticsearch in the field "alert_info"
    # It should return a dict of information relevant to what the alert does
    def get_info(self):
        return {'type': 'create_incident',
                'output_file': self.out_put_file, 'incident_id': self.incident_id}

    def store_events_to_es(self):
        for event in self.related_events[:99]:
            event['_index'] = self.rule['events_index']
            event['indexed_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            event['incident_id'] = self.incident_id
            event['alert_id'] = self.incident_attr.get('alert_id', None)
            event['incident_index'] = self.rule['incident_index']
            event['timestamp'] = event['@timestamp']
            event['created_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            event['updated_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            event['alert_criteria_type'] = "criteria1"
            self.incident_events.append(event)

        if 'hits' in self.additional_results:
            for event in self.additional_results['hits'][:99]:
                ev = event.get('_source', {})
                ev['_index'] = self.rule['events_index']
                ev['indexed_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                ev['incident_id'] = self.incident_id
                ev['alert_id'] = self.incident_attr.get('alert_id', None)
                ev['incident_index'] = self.rule['incident_index']
                ev['timestamp'] = ts_to_dt(ev['@timestamp'])
                ev['created_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                ev['updated_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                ev['alert_criteria_type'] = "criteria2"
                self.incident_events.append(ev)

        resp = helpers.bulk(self.es_client, self.incident_events)
        events_created = resp[0]
        events_errors = resp[1]
        elastalert_logger.info("A list of %(count)s events have created." % {"count": events_created})
        if len(events_errors):
            for er in events_errors:
                elastalert_logger.info("Error: %(error)s" % {"error": er})

    def store_incidents_to_es(self):
        new_status = "Uber Escalated"
        body = {
            "script": {
                "inline": "ctx._source.status='%s'" % new_status,
                "lang": "painless"
            },
            "query": {
                "bool": {
                    "must_not": [{"term": {"status.keyword": new_status}}],
                    "must": {"terms": {"_id": map(lambda i: str(i.get('id', '')), self.incident_tuple)}}
                }
            }
        }

        resp = self.es_client.update_by_query(index=self.rule['incident_index'],
                                              doc_type=self.incident_attr['doc_type'], body=body, params={'refresh': 'true'})
        elastalert_logger.info("A list of %(count)s incidents have updated with %(params)s"
                               % {"count": resp['updated'], "params": new_status})
