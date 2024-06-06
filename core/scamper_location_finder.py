import subprocess
import ipaddress
import re
import os 

class LocationFinder:
   


    def getPoPLocation(self, resolver, ctrl):
        try:
            if resolver == '9.9.9.9':
                resp = ctrl.do_dns('id.server','9.9.9.9',qclass = 'ch',qtype='txt',sync = True)
                resp = str(resp.an(0))
                
                if 'NXDOMAIN' in resp:
                    return 'NXDOMAIN_LOCATION_UNKNOWN'
                else:
                    pattern = r'\.(\w{3})\.'
                    match = re.search(pattern, resp)
                    code = match.group(1)
                    # Update: if not a 3-letter city code, return Error
                    if len(code) == 3:
                        return code.upper()
                    else:
                        return 'PARSE_ERROR_LOCATION_UNKNOWN'
            elif resolver == '1.1.1.1':
               
                resp = ctrl.do_dns('id.server','1.1.1.1',qclass = 'ch',qtype='txt',sync = True)
                resp = str(resp.an(0))
                if 'NXDOMAIN' in resp:
                    return 'NXDOMAIN_LOCATION_UNKNOWN'
                else:
                    # Update: if not a 3-letter city code, return Error
                    code = resp.split('"')[1]
                    if len(code) == 3:
                        return code.upper()
                    else:
                        return 'PARSE_ERROR_LOCATION_UNKNOWN'
            elif resolver == '208.67.220.220':
                resp = ctrl.do_dns('debug.opendns.com','208.67.220.220',qtype='txt',sync = True)
                pattern = r'\.(\w{3})'
                match = re.search(pattern, str(resp.ans(0)))
                code = match.group(1)
                # Update: if not a 3-letter city code, return Error
                if len(code) == 3:
                    return code.upper()
                else:
                    return 'PARSE_ERROR_LOCATION_UNKNOWN' 
            else:
                return 'UNKNOWN_RESOLVER_LOCATION_UNKNOWN'
        except AttributeError as err:
            return 'ATTRIBUTE_ERROR_LOCATION_UNKNOWN'
        except KeyError:
            return 'KEY_ERROR_LOCATION_UNKNOWN'
        except Exception as err:
            return 'UNKNOWN_ERROR_LOCATION_UNKNOWN'
            

   

    