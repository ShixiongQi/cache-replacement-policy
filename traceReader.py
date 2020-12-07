import sys
import scapy
from scapy.all import *
from scapy.utils import PcapReader
import hashlib

cacheList = [] # The cache list

def hashing(address):
    print("address: ", address)
    t_as_string = str(address)
    hash_object = hashlib.sha256(str(t_as_string).encode('utf-8'))
    hex_value = hash_object.hexdigest()
    # decimal_value = int(hex_value, 16)
    # index = decimal_value % int(cache_size)
    return hex_value

def __setup(filepath):
    global cacheList

    packets = rdpcap(filepath) # Read pcap file
    for data in packets:
        if 'TCP' in data:
            src_addr = data['IP'].src
            dst_addr = data['IP'].dst
            sport = data['TCP'].sport
            dport = data['TCP'].dport
            proto = data['IP'].proto
            t = (src_addr, dst_addr, sport, dport, proto) # IP 5Tuples
            hex_addr = hashing(t)
            cacheList.append(hex_addr)

filename = str(sys.argv[1])
__setup(filename)
print(cacheList)