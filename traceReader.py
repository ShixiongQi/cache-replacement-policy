import sys
import scapy
from scapy.all import *
from scapy.utils import PcapReader
import hashlib

cacheList = [] # The cache list

def hashing(address):
    # print("address: ", address)
    t_as_string = str(address)
    hash_object = hashlib.sha256(str(t_as_string).encode('utf-8'))
    hex_value = hash_object.hexdigest()
    # decimal_value = int(hex_value, 16)
    # index = decimal_value % int(cache_size)
    return hex_value

def __setup(filepath, max_trace_size):
    global cacheList
    packets = rdpcap(filepath, max_trace_size) # Read pcap file
    for data in packets:
        if 'TCP' or 'UDP' in data:
            try:
                src_addr = data['IP'].src
                dst_addr = data['IP'].dst
                if 'TCP' in data:
                    sport = data['TCP'].sport
                    dport = data['TCP'].dport
                else:
                    sport = data['UDP'].sport
                    dport = data['UDP'].dport
                proto = data['IP'].proto
                t = (src_addr, dst_addr, sport, dport, proto) # IP 5Tuples
                hex_addr = hashing(t)
                cacheList.append(hex_addr)
            except:
                print(repr(data))
                continue

filename = str(sys.argv[1])
max_trace_size = int(sys.argv[2])
__setup(filename, max_trace_size)
# print(cacheList)
print(len(cacheList))