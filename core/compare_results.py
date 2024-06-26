import csv
from datetime import datetime
from datetime import timedelta
import json

#TODO: Needs to be replaced with the real quad1 code.
def numFilledTTLs(x_ints, max_ttl):
    # Any number of cache hits per TTL get counted as one cache hit. 
    # TTL "epochs" start at unix time 0.
    ttl_epochs = []
    for x in x_ints:
        ttl_epochs.append(int(int(x.timestamp()) / max_ttl) * max_ttl)
    return len(set(ttl_epochs))

def coalesceHeadOrTail(lo, mid, hi):
    coalesced = []
    one = timedelta(seconds=1)
    two = timedelta(seconds=2)
    # If all three x_ints are a group, return one of them.
    if lo + one == mid and mid + one == hi:
        coalesced.append(mid)
    # If either two are a group, return one from that group and the ungrouped x_int.
    elif lo + one == mid:
        coalesced += [mid, hi]
    elif mid + one == hi:
        coalesced += [lo, mid]
    # Else, return all three.
    else:
        coalesced += [lo, mid, hi]
    #print("Coalesced head or tail: ", coalesced)
    return coalesced

def coalesce(x_ints):
    x_ints = sorted(set(x_ints))
    #print("Set of x_ints: ", x_ints)
    coalesced = []
    one = timedelta(seconds=1)
    two = timedelta(seconds=2)

    if len(x_ints) <= 1:
        return x_ints
    if len(x_ints) == 2:
        # If the two x_ints are a group, return one of them.
        if x_ints[0] + one == x_ints[1]:
            return [x_ints[0]]
        # Otherwise, return both.
        else:
            return x_ints
    if len(x_ints) == 3:
        coalesced += coalesceHeadOrTail(x_ints[0], x_ints[1], x_ints[2])
        return coalesced
    for i in range(0, (len(x_ints))):
        dummy_lolo = datetime(1990, 1, 1, 1, 1, 0)
        dummy_lo = datetime(1990, 1, 1, 1, 2, 0)
        dummy_hi = datetime(2120, 1, 1, 1, 1, 0)
        dummy_hihi = datetime(2120, 1, 1, 1, 2, 0)
        if i == 0:
            lolo = dummy_lolo
            lo = dummy_lo
            mid = x_ints[i]
            hi = x_ints[i+1]
            hihi = x_ints[i+2]
        if i == 1:
            lolo = dummy_lolo
            lo = x_ints[i-1]
            mid = x_ints[i]
            hi = x_ints[i+1]
            hihi = x_ints[i+2]
        if i == len(x_ints) -1:
            hihi = dummy_hihi
            hi = dummy_hi
            lolo = x_ints[i-2]
            lo = x_ints[i-1]
            mid = x_ints[i]
        if i == len(x_ints) - 2:
            hihi = dummy_hihi
            lolo = x_ints[i-2]
            lo = x_ints[i-1]
            mid = x_ints[i]
            hi = x_ints[i+1]

        # If I'm a group of one, count me.
        if lo < mid-one and hi > mid+one:
            coalesced.append(mid)
        # If I'm first in a group of two, don't count me.
        elif lo < mid-one and mid+one == hi and mid+two < hihi:
            continue
        # If I'm second in a group of two, append.
        elif lolo < mid-two and lo == mid-one and hi > mid+one:
            coalesced.append(mid)
        # If I'm first in a group of more than two, don't count me.
        elif lo < mid-one and hi == mid+one and hihi == mid + two:
            continue
        # If I'm part of a group that's at least 3 big, but not the first or last of the group, append.
        elif lo == mid-one and hi == mid + one:
            coalesced.append(mid)
        # If I'm the last in a group that's at least three big, don't count me.
        elif hi > mid+one and lo == mid - one:
            continue
        # Otherwise, I'm not part of a group, count me.
        else:
            coalesced.append(mid)
    return coalesced

def estimateFilledCaches(ark_data, resolver):
    x_ints = []
    tss = []
    ttls = []
    
    for (ts, ttl) in zip(ark_data['scamper_ts'], ark_data['ttl']):
        if ttl <= 0:
            continue
        x_ints.append(ts + timedelta(seconds=ttl))
        tss.append(ts)
        ttls.append(ttl)

    if resolver == '9.9.9.9' or resolver == '149.112.112.112' or resolver == 'OpenDNS' or '208.67' in str(resolver):
        # "Randall method" (remove first and last from group)
        coalesced_x_ints = coalesce(x_ints)
        #print("Estimate filled caches: ", coalesced_x_ints)
        return len(coalesced_x_ints)
    elif resolver == '1.1.1.1' or resolver == '1.0.0.1':
        # We can only see one cache hit per TTL
        return numFilledTTLs(x_ints, 10800)
    

# Takes data from a single Quad8 PoP
def estimateFilledQuad8Caches(ark_tss, ark_ttls):
    # We must discard all TTL lines that begin at the same time as a measurement arriving,
    # because that measurement might have filled a previously-unfilled frontend cache. This
    # would have poisoned the cache by placing a domain in it.

    # Map of 
    valid_ttl_line = {}
    # List of timestamps at which a TTL line starts
    line_starts = []
    # Map of timestamps of measurements to the time at which their TTL line starts
    ts_to_line_start = {}

    for ts, ttl in zip(ark_tss, ark_ttls):
        line_start = ts - timedelta(seconds=(10799 - ttl))
        ts_to_line_start[ts] = line_start
        line_starts.append(line_start)

    # Remove duplicates and sort
    line_starts = sorted(set(line_starts))

    for l in line_starts:
        valid_ttl_line[l] = True

    # Now eliminate TTL lines generated by ark nodes' cache hits
    for ts in sorted(ark_tss):
        for line_start in line_starts:
            diff = timedelta(seconds=0)
            if ts > line_start:
                diff = ts - line_start
            else:
                diff = line_start - ts
            if diff <= timedelta(seconds=0):
                valid_ttl_line[line_start] = False
    
    # Count all valid TTL lines
    valid_lines = []
    for line_start in valid_ttl_line:
        if valid_ttl_line[line_start]:
            valid_lines.append(line_start)

    return set(valid_lines)
