import sys
import hashlib
import scapy
from scapy.all import *
from scapy.utils import PcapReader

cache = [] # Flow Director
cacheList = [] # The cache list

def hashing(address):
    print("address: ", address)
    t_as_string = str(address)
    hash_object = hashlib.sha256(str(t_as_string).encode('utf-8'))
    hex_value = hash_object.hexdigest()
    # decimal_value = int(hex_value, 16)
    # index = decimal_value % int(cache_size)
    return hex_value

def cache_init(size):
    cache.clear()
    for i in range(0, size):
        tmp = [[],[],[]] # [IP 5Tuples],[frequency_counter],[CRF value]
        cache.append(tmp)

def reorder_cache_by_recency(tag, start):
    for s in range(start, len(cache)):
        cache[s - 1] = cache[s]
    cache[-1] = tag

def reorder_cache_by_frequency(): # O(nlogn)
    if len(cache) <= 1:
        return cache
    pivot = cache[0][1]  # base value
    left = [cache[i] for i in range(1, len(cache)) if cache[i][1] < pivot] 
    right = [cache[i] for i in range(1, len(cache)) if cache[i][1] >= pivot]
    cache = quickSort(left) + [pivot] + quickSort(right)

def access_cache(address, replacement_policy):
    # tag = int(address / len(cache))
    tag = address

    for pos in range(0, len(cache)):
        if cache[pos][0] == tag:
            # The flow is cached
            # Update the metadata of the flow
            if replacement_policy == "LRU":
                # LRU is enabled
                # Reorder the cache by recency
                reorder_cache_by_recency(tag, pos + 1)
            else if replacement_policy == "LFU":
                # LFU is enabled
                # Update the frequency counter of the flow
                cache[pos][1] = cache[pos][1] + 1
                # Reorder the cache by frequency
                reorder_cache_by_frequency()
            else if replacement_policy == "LRFU": # TODO: develop LRFU policy
                # LRFU is enabled
                # Updated the CRF value of the flow
                cache[pos][2] = cache[pos][2] + 1
                # Reorder the cache by frequency
                reorder_cache_by_frequency()
            else:
                print("Please select LRU/LFU/LRFU")
                exit(1)
            return True

    # The flow is not cached
    # replace the flow with designated policy
    if replacement_policy == "LRU":
        reorder_cache_by_recency(tag, 1)
    else if replacement_policy == "LFU":
        cache[0] = tag # Replace the least frequently used flow
        cache[0][1] = 1 # Initialize the frequency counter
        reorder_cache_by_frequency()
    else if replacement_policy == "LRFU":
        cache[0] = tag # Replace the least frequently used flow
        cache[0][2] = 1 # Initialize the frequency counter
        reorder_cache_by_frequency()
    return False

def simulate(cache_size, accesses, replacement_policy):
    print("== Fully associated cache ==")
    cache_init(cache_size)
    miss = 0
    for a in range(0, len(accesses)):
        # print(accesses[a])
        if access_cache(accesses[a], replacement_policy) == False:
            miss = miss + 1
    miss_rate = float(miss / float(len(accesses)))
    print("Miss rate: ", miss_rate)
    print("Hit rate: ", 1 - miss_rate)

def __setup(filepath, max_trace_size):
    global cacheList
    trace_cnt = 0
    packets = rdpcap(filepath) # Read pcap file
    for data in packets:
        if trace_cnt >= max_trace_size:
            break
        if 'TCP' in data:
            src_addr = data['IP'].src
            dst_addr = data['IP'].dst
            sport = data['TCP'].sport
            dport = data['TCP'].dport
            proto = data['IP'].proto
            t = (src_addr, dst_addr, sport, dport, proto) # IP 5Tuples
            hex_addr = hashing(t)
            cacheList.append(hex_addr)
            trace_cnt = trace_cnt + 1

if __name__ == "__main__":
    filename = str(sys.argv[1])
    cache_size = int(sys.argv[2])
    max_trace_size = int(sys.argv[3])
    replacement_policy = str(sys.argv[4]) # LRU LFU LRFU

    if cache_size <= max_trace_size:
        __setup(filename, max_trace_size) # import trace file
        accesses = cacheList
        simulate(cache_size, accesses, replacement_policy) # run the replacement policy
    else:
        print("Trace size is less than the cache size")
        exit(1)
