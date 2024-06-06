from . import scamper_dns_lib as dns_lib
from . import scamper_location_finder as location_finder
from . import config
from .utils import printAndLog
from .compare_results import estimateFilledCaches
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from traceback import print_exc
import threading
import time
import logging
import signal
import sys
import concurrent.futures
import os
import subprocess
import argparse
import random
from scamper import ScamperCtrl

my_logger = logging.getLogger('TrufferHunter')

class BaseSearcher:
    domains = []
    resolver = ''
    repeats = 10 # number of DNS requests per domain

    # Name of this host
    hostname = ''

    # Location finder: finds out which PoPs this node is currently hitting (at a best guess)
    # Needs to be reinitialized to set the DNS command in __init__
    location_finder = location_finder.LocationFinder()

    # List of scripts for DNS multi-domain on command line mode
    searcher_scripts = []

    # Script in a string for avoiding writing files
    scripts = {}

    def commandFileName(self, resolver):
        return resolver.replace('.','-') + '.sh'

    

    

    '''
    Over some time interval smaller than a minute, request all domains from self.resolvers.
    '''
    def searchForDomains(self, ctrl):
        search_results = []
        unknown_resolvers = []
        for resolver in self.resolvers:
         
            
            # Find out which PoP this node currently hits
            loc = self.location_finder.getPoPLocation(resolver,ctrl)
            if 'UNKNOWN' in loc:
                unknown_resolvers.append(resolver)
            
            for domain in self.domains:
                for i in range(self.repeats):
                    o = ctrl.do_dns(domain,resolver,qtype='A',rd=True, sync=True)
                    search_results.append(dns_lib.ParseScamperOutput(o, loc))  # TODO refactor to use all instances

                
                    

        if len(unknown_resolvers) > 0:
            print('WARNING: Erroneous responses were returned for the location queries to the following resolvers:', unknown_resolvers)
            print('These responses did not match the usual format of responses given by the public resolvers.')
            print('Your ISP may be transparently proxying some or all of your DNS queries. For more info, see https://github.com/ucsdsysnet/trufflehunter/blob/master/README.md#isp-interception-of-dns-queries')
        return search_results

    def __init__(self, resolvers, hostname, domains):
        self.location_finder = location_finder.LocationFinder()
        self.resolvers = resolvers
        self.hostname = hostname
        self.domains = domains
        self.repeats = config.Config["search"]["number_of_attempts"]

        

class Searcher(BaseSearcher):
    # Todo: Determine how many iterations we want to probe
    iterations = 1
    threads = []
    hostname = ''
    start_time = datetime.now()

    def runBaseSearcher(self):
        self.start_time = datetime.now()
        ctrl = ScamperCtrl(unix="/tmp/scamper")
        base_searcher = BaseSearcher(self.resolvers, self.hostname, self.domains)
        start_time = datetime.now()
        all_search_results = []
        for i in range(0, self.iterations):
            # Search for domains
            search_results = base_searcher.searchForDomains(ctrl)
            all_search_results += search_results
            end_time = datetime.now()

            # On the last iteration, don't sleep: we need to rotate the result file out.
            if i == self.iterations-1:
                break
            
            # Sleep for the remainder of the minute, but calculate that minute using total start time so errors don't accumulate
            time_remaining = (self.start_time + timedelta(minutes=(i+1)) - end_time).total_seconds()
            if time_remaining <= 0:
                my_logger.debug("Negative time_remaining in runBaseSearcher:\n")
                my_logger.debug("\tself.start_time: "+str(self.start_time)+"\n")
                my_logger.debug("\ttimedelta(minutes=(i+1)): " + str(timedelta(minutes=(i+1))) + "\n")
                my_logger.debug("\ti: "+ str(i))
                my_logger.debug("\tend_time: " + str(end_time)+"\n")
                my_logger.debug("\ttime_remaining: "+ str(time_remaining) + "\n")
            elif time_remaining < 60 and time_remaining >= 0:
                time.sleep(time_remaining)
            elif time_remaining > 60:
                my_logger.debug("time_remaining greater than 60 in runBaseSearcher: " + str(time_remaining) + "\n")
        
        # key for first dict: domain name
        # key for second dict: resolver
        # key for third dict: data entries
        # location is fixed for one resolver from one vantage point

        # construct initial state for all domains and all resolvers
        domain_to_pop_to_data_mapping = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        for requested_domain in self.domains:
            for requested_resolver in self.resolvers:
                _ = domain_to_pop_to_data_mapping[requested_domain][requested_resolver]["scamper_ts"]
                _ = domain_to_pop_to_data_mapping[requested_domain][requested_resolver]["ttl"]
                _ = domain_to_pop_to_data_mapping[requested_domain][requested_resolver]["pop_location"]
        
        printAndLog("Raw scamper Results:")
        for r in all_search_results:
            printAndLog(r)
            if r["requested_domain"].strip(".").strip("\r\n") in self.domains and r["resolver"] in self.resolvers:
                
                resolver_to_data_mapping = domain_to_pop_to_data_mapping[r["requested_domain"].strip(".").strip("\r\n")]
                resolver_to_data_mapping[r["resolver"]]["scamper_ts"].append(r["scamper_ts"])
                resolver_to_data_mapping[r["resolver"]]["ttl"].append(r["ttl"])
                resolver_to_data_mapping[r["resolver"]]["pop_location"].append(r["pop_location"])
                

        for requested_domain in domain_to_pop_to_data_mapping.keys():
            resolver_to_data_mapping = domain_to_pop_to_data_mapping[requested_domain]
            for resolver in resolver_to_data_mapping.keys():
                if len(resolver_to_data_mapping[resolver]["ttl"]) == 0:
                    print("\nDomain:{}, Resolver:{}, ERROR_NO_DATA_AVAILABLE".format(requested_domain.rstrip("."), resolver))
                else:
                    #printAndLog(pop_to_data_mapping[key]["ttl"])
                    count = estimateFilledCaches(resolver_to_data_mapping[resolver],resolver)
                    resolver_location = all_search_results[0]['pop_location']
                    print("\nDomain:{}, Resolver:{}, Location: {}, Cache Count: {}, Last Probed: {}".format(requested_domain.rstrip("."), resolver, resolver_location, count, self.start_time.strftime("%Y-%m-%d %X %Z")))
        

    def __init__(self, resolvers, domains, hostname='UNKNOWN_HOST'):
        self.hostname = hostname
        self.domains = domains
        self.resolvers = resolvers
               