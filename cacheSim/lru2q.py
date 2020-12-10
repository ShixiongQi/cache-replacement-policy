import sys, time
import hashlib
import scapy
from scapy.all import *
from scapy.utils import PcapReader

class lru2q(object):
    def __init__(self):
        self.buffer_cache = [] # Flow Director
        self.his_cache = [] # Traffic Segregator
        self.cacheList = [] # The cache list

    def cache_init(self, total_size, buffer_size):
        his_size = total_size - buffer_size
        self.buffer_cache.clear()
        self.his_cache.clear()
        for i in range(buffer_size):
            self.buffer_cache.append(0)
        for i in range(his_size):
            self.his_cache.append(0)

    def reorder_cache_by_recency(self, key, start, _cache):
        for s in range(start, len(_cache)):
            _cache[s - 1] = _cache[s]
        _cache[-1] = key

    def remove_flow_in_cache(self, start, _cache):
        for s in range(0, start):
            _cache[start - s] = _cache[start - s - 1]
        _cache[0] = 0

    def access_cache(self, key):
        for pos in range(0, len(self.buffer_cache)):
            if self.buffer_cache[pos] == key: # Check if the flow is in Flow Director
                # Hit in the traffic segregator, update recency in buffer_cache
                self.reorder_cache_by_recency(key, pos + 1, self.buffer_cache)
                return True
        for pos in range(0, len(self.his_cache)):
            if self.his_cache[pos] == key: # Check if the flow is in Traffic Segregator
                # Hit in the traffic segregator, move the flow to buffer_cache
                self.reorder_cache_by_recency(key, 1, self.buffer_cache)
                # remove the flow from his_cache
                self.remove_flow_in_cache(pos, self.his_cache)
                return True
        # The flow is not cached, insert the flow into Traffic Segregator
        # 1st accessed, insert to his_cache
        self.reorder_cache_by_recency(key, 1, self.his_cache)
        return False

    def simulate(self, total_cache_size, buffer_size):
        print("== Fully associated cache ==")
        self.cache_init(total_cache_size, buffer_size)
        miss = 0
        for a in range(0, len(self.cacheList)):
            # print(self.cacheList[a])
            # print(self.cache)
            # input("Enter")
            if self.access_cache(self.cacheList[a]) == False:
                miss = miss + 1
        miss_rate = float(miss / float(len(self.cacheList)))
        print("# of miss: {}\t # of access: {}".format(miss, len(self.cacheList)))
        print("Miss rate: ", miss_rate)
        print("Hit rate: ", 1 - miss_rate)

    def setup(self, filepath):
        with open(filepath, 'r') as file:
            for line in file:
                temp = line.split('\n')[0]
                self.cacheList.append(int(temp, 16))
