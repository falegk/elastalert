import dateutil.parser
import copy
import datetime
import sys
import threading

from blist import sortedlist
from elastalert.util import dt_to_ts
from elastalert.util import EAException
from elastalert.util import elastalert_logger
from elastalert.util import hashable
from elastalert.util import lookup_es_key
from elastalert.util import new_get_event_ts
from elastalert.util import pretty_ts
from elastalert.util import total_seconds
from elastalert.util import ts_now
from elastalert.util import elasticsearch_client
from elastalert.util import dt_to_ts

from elastalert.ruletypes import RuleType
from elastalert.ruletypes import EventWindow
from elastalert.util import ts_to_dt


def get_query(filters, starttime=None, endtime=None, sort=True, timestamp_field='@timestamp', to_ts_func=dt_to_ts, desc=False,
              five=False):
    """ Returns a query dict that will apply a list of filters, filter by
    start and end time, and sort results by timestamp.

    :param filters: A list of Elasticsearch filters to use.
    :param starttime: A timestamp to use as the start time of the query.
    :param endtime: A timestamp to use as the end time of the query.
    :param sort: If true, sort results by timestamp. (Default True)
    :return: A query dictionary to pass to Elasticsearch.
    """
    starttime = to_ts_func(starttime)
    endtime = to_ts_func(endtime)
    filters = copy.copy(filters)
    es_filters = {'filter': {'bool': {'must': filters}}}
    if starttime and endtime:
        es_filters['filter']['bool']['must'].insert(0, {'range': {timestamp_field: {'gt': starttime,
                                                                                    'lte': endtime}}})
    if five:
        query = {'query': {'bool': es_filters}}
    else:
        query = {'query': {'filtered': es_filters}}
    if sort:
        query['sort'] = [{timestamp_field: {'order': 'desc' if desc else 'asc'}}]
    return query

class ExtensionFrequencyRule(RuleType):
    """ A rule that matches if min_num_events or range of min_num_events & max_num_events number of
        events occur within a timeframe.
        This type of rule is used with different ways based on type of its data.

        * Search for Logs/Events with uber_incident: False [Default]
            Returns matched hits
        * Search for Incidents with uber_incident: True
            Returns Aggregations & hits
    """

    required_options = frozenset(['min_num_events', 'timeframe'])

    def __init__(self, *args):
        super(ExtensionFrequencyRule, self).__init__(*args)
        # When uber_incident is True then used an aggregate system in the incidents
        self.uber_incident = self.rules.get('uber_incident', False)

        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.get_ts = new_get_event_ts(self.ts_field)
        self.attach_related = self.rules.get('attach_related', False)
        self.min_num_events = self.rules.get('min_num_events', False)
        self.max_num_events = self.rules.get('max_num_events', False)
        self.max_related_events = self.rules.get('max_related_events', 100)
        self.correlated_values = []
        self.occurrences_keys = []
        self.additional_results = {}
        self.important_fields = self.rules.get('important_fields_list', [])
        self.additional_filters = self.rules.get('additional_filters', False)
        # Used like self.occurrences to store EventWindow for the additional_results occurrences
        self.additional_results_occurrences = {}
        self.additional_results_occurrences_keys = []

    def additional_filters_match(self, rules, key):
        rule = rules
        es = elasticsearch_client(rules)
        starttime = rules['starttime']
        endtime = ts_now()
        additional_filters = rules['additional_filters']

        rule_query = additional_filters.get('filter', [])[0].get('query', {}).get('query_string', {})['query']
        additional_filters.get('filter', [])[0].get('query', {}).get('query_string', {})['query'] = \
            "%s AND %s" % (rule_query, key) if rule_query else rule_query
        new_filters = []
        if es.is_atleastfive():
            rules['five'] = True
            for es_filter in additional_filters.get('filter', []):
                if es_filter.get('query'):
                    new_filters.append(es_filter['query'])
                else:
                    new_filters.append(es_filter)
        else:
            new_filters = additional_filters.get('filter', [])
            rules['five'] = False

        query = get_query(new_filters, starttime, endtime, five=rules['five'])
        index = rules['index']

        old_starttime = pretty_ts(rule.get('original_starttime'), rule.get('use_local_time'))
        elastalert_logger.debug("[Additional Filters] Query: %s " % (query))

        res = es.search(body=query, index=index, size=rules.get('max_query_size', 100),
                        ignore_unavailable=True, timeout='50s')
        if es.is_atleastseven():
            total_hits = int(res['hits']['total']['value'])
        else:
            total_hits = int(res['hits']['total'])

        hits = res['hits']['hits']
        num_hits = len(hits)
        # Sets self.additional_results_occurrences
        cv = self.set_correlated_in_additional_results(hits)
        self.additional_results = { "hits": hits, "num_hits": num_hits, "total_hits": total_hits, "correlated_values": cv }
        elastalert_logger.info("[Additional Filters] Query Total Hits: %s Num Hits: %s" % (total_hits, num_hits))
        return self.additional_results

    def add_count_data(self, data):
        """ Add count data to the rule. Data should be of the form {ts: count}. """
        if len(data) > 1:
            raise EAException('add_count_data can only accept one count at a time')

        (ts, count), = data.items()

        event = ({self.ts_field: ts}, count)
        self.occurrences.setdefault('all', EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(event)
        self.check_for_match('all')

    def add_terms_data(self, terms):
        for timestamp, buckets in terms.items():
            for bucket in buckets:
                event = ({self.ts_field: timestamp,
                          self.rules['query_key']: bucket['key']}, bucket['doc_count'])
                self.occurrences.setdefault(bucket['key'], EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(event)
                self.check_for_match(bucket['key'])

    def add_data(self, data):
        if 'query_key' in self.rules:
            qk = self.rules['query_key']
        else:
            qk = None

        for event in data:
            if qk:
                if self.uber_incident:
                    # TODO; Change it to work with dynamic nested qk
                    #  (ex for. important_fields.key => important_fields: [{'key': 'value'}])
                    cv_value = lookup_es_key(event, 'correlated_values')
                    if isinstance(cv_value, (list, dict)):
                        key = hashable(cv_value[0].get("value", ''))
                    else:
                        key = hashable(lookup_es_key(event, qk))
                else:
                    key = hashable(lookup_es_key(event, qk))
            else:
                # If no query_key, we use the key 'all' for all events
                key = 'all'
            # Store the timestamps of recent occurrences, per key
            self.occurrences.setdefault(key, EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append((event, 1))

        # Keep all uniq query keys
        self.occurrences_keys = list(self.occurrences)

        for oc_key in self.occurrences_keys:
            self.check_for_match(oc_key, end=False)

        # We call this multiple times with the 'end' parameter because subclasses
        # may or may not want to check while only partial data has been added
        if key in self.occurrences:  # could have been emptied by previous check
            self.check_for_match(key, end=True)

    # returns a dict of correlated values
    # and also initialize self.additional_results_occurrences and self.additional_results_occurrences_keys
    def set_correlated_in_additional_results(self, data):
        cv = {}
        if 'query_key' in self.additional_filters:
            qk = self.additional_filters['query_key']
        else:
            qk = None

        for event in data:
            if qk:
                key = hashable(lookup_es_key(event['_source'], qk))
            else:
                # If no query_key, we use the key 'all' for all events
                key = 'all'

            if '@timestamp' in event['_source']:
                event['_source']['@timestamp'] = ts_to_dt(event['_source']['@timestamp'])

            # Store the timestamps of recent occurrences, per key
            self.additional_results_occurrences.setdefault(key, EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append((event['_source'], 1))

        # Keep all uniq query keys
        self.additional_results_occurrences_keys = list(self.additional_results_occurrences)
        for k in self.additional_results_occurrences_keys:
            cv[k] = { "qk": self.additional_filters['query_key'], "value": k, "counts": self.additional_results_occurrences[k].count() }
        return cv

    def add_events_from_occurrences(self, event, key):
        if self.attach_related:
            related_events = [data[0] for data in self.occurrences[key].data[:-1][:self.max_related_events]]
            # additional_result_events = [data[0] for data in self.occurrences[key].data[:-1][:self.max_related_events]]
            related_events.append(event.copy())
            event['related_events'] = related_events
            event['correlated_values'] = self.correlated_values
            event['additional_results'] = self.additional_results
            event['important_fields_list'] = \
                self.set_important_fields(event['related_events']) if len(self.important_fields) > 0 else []
        self.correlated_values = []
        self.add_match(event)
        self.occurrences.pop(key)

    def append_correlated_values(self, key):
        if 'query_key' in self.rules:
            self.correlated_values.append({"qk": self.rules['query_key'], "value": key, "counts": self.occurrences[key].count()})

    def append_hits_from_additional_filters(self, key):
        return True

    def criteria_for_match(self, key):
        # If 'trigger_alert_by_events' exists then check if additional results count
        # is bigger than additional_filters['min_num_events']
        if self.additional_filters and self.additional_filters['trigger_alert_by_events']:
            if self.additional_filters['min_num_events'] > self.additional_results['total_hits']:
                return None

        if self.min_num_events and self.max_num_events:
            if self.rules['min_num_events'] <= self.occurrences[key].count() <= self.rules['max_num_events']:
                self.append_correlated_values(key)
                event = self.occurrences[key].data[-1][0]
                self.add_events_from_occurrences(event, key)
        elif self.min_num_events:
            if self.occurrences[key].count() >= self.rules['min_num_events']:
                self.append_correlated_values(key)
                event = self.occurrences[key].data[-1][0]
                self.add_events_from_occurrences(event, key)

    def check_for_match(self, key, end=False):
        # elastalert_logger.info("*** 2. check_for_match ***: %s" % (key))
        # The 'end' parameter depends on whether this was called from the
        # middle or end of an add_data call and is used in subclasses
        if self.additional_filters:
            self.additional_filters_match(self.rules, key)

        self.criteria_for_match(key)


    def garbage_collect(self, timestamp):
        # elastalert_logger.info("*** 3. garbage_collect ***")
        """ Remove all occurrence data that is beyond the timeframe away """
        stale_keys = []
        for key, window in self.occurrences.items():
            if timestamp - lookup_es_key(window.data[-1][0], self.ts_field) > self.rules['timeframe']:
                stale_keys.append(key)
        list(map(self.occurrences.pop, stale_keys))

    def get_match_str(self, match):
        lt = self.rules.get('use_local_time')
        match_ts = lookup_es_key(match, self.ts_field)
        starttime = pretty_ts(dt_to_ts(ts_to_dt(match_ts) - self.rules['timeframe']), lt)
        endtime = pretty_ts(match_ts, lt)
        message = 'At least %d events occurred between %s and %s\n\n' % (self.rules['min_num_events'],
                                                                         starttime,
                                                                         endtime)
        # elastalert_logger.info(message)
        return message

    # Generates and returns a list from important fields
    # Result: self.important_list = self.set_important_fields(events)
    #   => [{"field_name": 'tags', "value": []}, {"field_name": 'host', "value": []}]
    def set_important_fields(self, events):
        results = {}
        list = []
        for event in events:
            for field in self.important_fields:
                splited_field = field.split(".")
                if splited_field[0] in list(event):
                    if field in results:
                        if len(splited_field) == 1:
                            value = event[splited_field[0]]
                        else:
                            value = event[splited_field[0]][splited_field[1]]
                        if value not in results[field]: results[field].append(value)
                    else:
                        value = event[splited_field[0]] if len(splited_field) == 1 else event[splited_field[0]][splited_field[1]]
                        results[field] = [value]
        for key, value in results.items():
            list.append({"field_name": key, "value": value})
        return list


class ExtensionCardinalityRule(RuleType):
    """ A rule that matches if cardinality of a field is above or below a threshold within a timeframe """
    required_options = frozenset(['timeframe', 'cardinality_field'])

    def __init__(self, *args):
        super(ExtensionCardinalityRule, self).__init__(*args)
        if 'max_cardinality' not in self.rules and 'min_cardinality' not in self.rules:
            raise EAException("CardinalityRule must have one of either max_cardinality or min_cardinality")
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.get_ts = new_get_event_ts(self.ts_field)
        self.cardinality_field = self.rules['cardinality_field']
        self.cardinality_cache = {}
        self.first_event = {}
        self.timeframe = self.rules['timeframe']
        self.min_num_events = self.rules.get('min_num_events', False)
        self.max_num_events = self.rules.get('max_num_events', False)

    def add_data(self, data):
        qk = self.rules.get('query_key')
        for event in data:
            if qk:
                key = hashable(lookup_es_key(event, qk))
            else:
                # If no query_key, we use the key 'all' for all events
                key = 'all'

            # Store the timestamps of recent occurrences, per key
            self.occurrences.setdefault(key, EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append((event, 1))

        # Check min and between query keys count
        if self.min_num_events and self.max_num_events:
            if not (self.rules['min_num_events'] <= self.occurrences[key].count() <= self.rules['max_num_events']):
                return None
        elif self.min_num_events:
            if self.occurrences[key].count() < self.rules['min_num_events']:
                return None

        for event in data:
            if qk:
                key = hashable(lookup_es_key(event, qk))
            else:
                # If no query_key, we use the key 'all' for all events
                key = 'all'
            self.cardinality_cache.setdefault(key, {})
            self.first_event.setdefault(key, event[self.ts_field])
            value = hashable(lookup_es_key(event, self.cardinality_field))

            if value is not None:
                # Store this timestamp as most recent occurence of the term
                self.cardinality_cache[key][value] = event[self.ts_field]
                self.check_for_match(key, event)

    def check_for_match(self, key, event, gc=True):
        # Check to see if we are past max/min_cardinality for a given key
        timeframe_elapsed = event[self.ts_field] - self.first_event.get(key, event[self.ts_field]) > self.timeframe
        if (len(self.cardinality_cache[key]) > self.rules.get('max_cardinality', float('inf')) or
                (len(self.cardinality_cache[key]) < self.rules.get('min_cardinality', float('-inf')) and timeframe_elapsed)):
            # If there might be a match, run garbage collect first, as outdated terms are only removed in GC
            # Only run it if there might be a match so it doesn't impact performance
            if gc:
                # self.garbage_collect(event[self.ts_field])
                timestamp = event[self.ts_field]
                for qk, terms in self.cardinality_cache.items():
                    for term, last_occurence in terms.items():
                        if timestamp - last_occurence > self.rules['timeframe']:
                            self.cardinality_cache[qk].pop(term)

                    # Create a placeholder event for if a min_cardinality match occured
                    if 'min_cardinality' in self.rules:
                        event.update({self.ts_field: timestamp})
                        if 'query_key' in self.rules:
                            event.update({self.rules['query_key']: qk})
                        self.check_for_match(qk, event, False)

                self.check_for_match(key, event, False)
            else:
                related_events = [data[0] for data in self.occurrences[key].data[:-1]]
                related_events.append(event.copy())
                self.first_event.pop(key, None)
                event.update({"related_events": related_events})
                self.add_match(event)

    def garbage_collect(self, timestamp):
        """ Remove all occurrence data that is beyond the timeframe away """
        for qk, terms in self.cardinality_cache.items():
            for term, last_occurence in terms.items():
                if timestamp - last_occurence > self.rules['timeframe']:
                    self.cardinality_cache[qk].pop(term)

            # Create a placeholder event for if a min_cardinality match occured
            if 'min_cardinality' in self.rules:
                event = {self.ts_field: timestamp}
                if 'query_key' in self.rules:
                    event.update({self.rules['query_key']: qk})
                self.check_for_match(qk, event, False)

    def get_match_str(self, match):
        lt = self.rules.get('use_local_time')
        starttime = pretty_ts(dt_to_ts(ts_to_dt(match[self.ts_field]) - self.rules['timeframe']), lt)
        endtime = pretty_ts(match[self.ts_field], lt)
        if 'max_cardinality' in self.rules:
            message = ('A maximum of %d unique %s(s) occurred since last alert or between %s and %s\n\n' % (self.rules['max_cardinality'],
                                                                                                            self.rules['cardinality_field'],
                                                                                                            starttime, endtime))
        else:
            message = ('Less than %d unique %s(s) occurred since last alert or between %s and %s\n\n' % (self.rules['min_cardinality'],
                                                                                                         self.rules['cardinality_field'],
                                                                                                         starttime, endtime))
        return message
