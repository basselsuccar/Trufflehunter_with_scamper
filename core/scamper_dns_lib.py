from . import config 
from datetime import datetime
import subprocess
import re
import time
import logging
from datetime import datetime
'''
Records the relevant pieces of the output of scamper.
'''
class DnsResponse:
    status = ''
    opcode = ''
    flags = []
    qtype = ''
    rtt = -1
    # The timestamp returned by Dig in the line starting with ';; WHEN:'
    dig_ts = datetime.now()
    # The time at which the response was received, at ms granularity
    ts = datetime.now()
    requested_domain = ''
    domain = ''
    ttl = -1
    # Can be CNAME, A, NS, or AAAA afaik
    r_type = ''
    ip = ''
    resolver = ''
    # Recursion Desired (RD) flag in request. Dig assumes true if not specified.
    rd = True


    def printSerialized(self):
        print('Domain: ' + self.domain)
        print('Status: ' + self.status)
        print('Opcode: ' + self.opcode)
        print('Query type: ' + self.qtype)
        print('RTT: ' + str(self.rtt) + 'ms')
        print('Dig timestamp: ' + str(self.dig_ts))
        print('TTL: ' + str(self.ttl))
        print('Response type: ' + self.r_type)
        print('IP: ' + self.ip)
        print('Deprecated timestamp: ' + str(self.ts))
        print('Resolver: ', self.resolver)

    def __init__(self, scamper_output, ts):
            parser = ScamperParser(scamper_output, ts)
            parser.parse(scamper_output, ts)
        
        
        # self.printSerialized()

class ScamperParser(DnsResponse):

    def __getitem__(self, index):
        return getattr(self,index)

    def parse(self, scamper_output, ts, pop_location):
        # add loc info
        if pop_location != 'NO_LOCATION_SPECIFIED':
            self.pop_location = pop_location

        self.ts = ts
        self.requested_domain = scamper_output.qname
        self.rtt = scamper_output.rtt.total_seconds() * 1000  
        aware_dt = datetime.fromisoformat(str(scamper_output.rx))
        self.scamper_ts = aware_dt.replace(tzinfo=None,microsecond = 0)
        self.resolver = str(scamper_output.dst)
        answer = scamper_output.an(0)
        self.ip = answer.addr if answer is not None else ''
        self.ttl = answer.ttl if answer is not None else -1
        self.r_type = answer.rtype if answer is not None else ''
        self.domain = answer.name if answer is not None else ''
    
    
    def __repr__(self):
        string = ""
        string += 'Domain: ' + self.domain + ", "
        string += 'RTT: ' + str(self.rtt) + 'ms' + ", "
        string += 'Scamper timestamp: ' + str(self.scamper_ts) + ", "
        string += 'TTL: ' + str(self.ttl) + ", "
        string += 'Response type: ' + str(self.r_type) + ", "
        string += 'IP: ' + str(self.ip) + ", "
        string += 'Deprecated timestamp: ' + str(self.ts) + ", "
        string += 'Resolver: ' + str(self.resolver) + ", "
        return string



    def __init__(self, scamper_output, ts,loc='NO_LOCATION_SPECIFIED'):
        self.parse(scamper_output, ts,loc)




# def makeDigRequest(resolver, target, recursion_desired, raw_result_filename='', dig_cmd='dig', loc='None', hostname='UNKNOWN_HOSTNAME'):
#     recurse_flag = '+recurse'
#     if resolver[0] != '@':
#         resolver = '@' + resolver
#     if not recursion_desired:
#         recurse_flag = '+norecurse'
#     try:
#         resp = subprocess.check_output([dig_cmd, resolver, target, recurse_flag], universal_newlines=True)
#         ts = datetime.utcnow()
#     except subprocess.CalledProcessError as err:
#         logging.error('Check_output failed for dig, err = ', err)
#         return
    
#     if raw_result_filename != '':
#         query = dig_cmd + ' ' + resolver + ' ' + target
#         if not recursion_desired:
#             query += ' ' + recurse_flag
#         dns_file = DnsFile(raw_result_filename)
#         dns_file.writeDigResults(ts, query, resp, raw_result_filename)

#     if config.Config["other"]["verbose"] == True:
#         # CSV file. Columns:
#         # hostname, ts, resolver, requested_domain, recursion_desired, response_domain, status, opcode, rtt, dig_ts, ttl, response_type, ip, pop_location
#         # Example: Taliesin,2020-02-05 00:33:35.342429,8.8.8.8,a.thd.cc,False,a.thd.cc.,NOERROR,QUERY,6,2020-02-04 16:33:35,172,A,104.31.95.14,lax,
#         # ts, resolver, requested_domain, and recursion_desired are request parameters. Everything else comes from the response.
#         # Note that ts is in UTC and dig_ts is in the local time of the machine running the code
#         r = DnsResponse(resp, ts)
#         # r.printSerialized()
#         row = hostname + ',' + str(r.ts) + ',' + resolver.replace('@','') + ',' + target + ',' + str(recursion_desired) + ',' + r.domain + ',' + r.status + ',' + r.opcode + ',' + str(r.rtt) + ',' + str(r.dig_ts) + ',' + str(r.ttl) + ',' + r.r_type + ',' + r.ip + ',' + loc + ','
#         printAndLog(row)
    
#     return DnsResponse(resp, ts)


def ParseScamperOutput(scamper_output, loc='NO_LOCATION_SPECIFIED'):
 
        
    
    ts = datetime.utcnow()
        
    return ScamperParser(scamper_output, ts,loc)
