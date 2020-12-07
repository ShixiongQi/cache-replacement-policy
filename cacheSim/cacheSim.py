import sys
import hashlib
import scapy
from scapy.all import *
from scapy.utils import PcapReader

class cacheSim(object):
    def __init__(self):
        self.cache = [] # Flow Director
        self.cacheList = [] # The cache list

    def cache_init(self, size):
        self.cache.clear()
        for i in range(0, size):
            tmp = [0,0,0] # [IP 5Tuples],[frequency_counter],[CRF value]
            self.cache.append(tmp)

    def reorder_cache_by_recency(self, tag, start):
        for s in range(start, len(self.cache)):
            self.cache[s - 1][0] = self.cache[s][0]
        self.cache[-1][0] = tag

    def reorder_cache_by_frequency(self, _cache): # O(nlogn)
        if len(_cache) <= 1:
            return _cache
        pivot = _cache[0][1]  # base value
        left = [_cache[i] for i in range(1, len(_cache)) if _cache[i][1] < pivot] 
        right = [_cache[i] for i in range(1, len(_cache)) if _cache[i][1] >= pivot]
        return self.reorder_cache_by_frequency(left) + [_cache[0]] + self.reorder_cache_by_frequency(right)
    
    def reorder_cache_by_recency_frequency(self, _cache):
        

    def access_cache(self, address, replacement_policy):
        for pos in range(0, len(self.cache)):
            # print("\n{}\n{}".format(cache[pos][0],address))
            if self.cache[pos][0] == address:
                # The flow is cached
                # Update the metadata of the flow
                if replacement_policy == "LRU":
                    # LRU is enabled
                    # Reorder the cache by recency
                    self.reorder_cache_by_recency(address, pos + 1)
                elif replacement_policy == "LFU":
                    # LFU is enabled
                    # Update the frequency counter of the flow
                    self.cache[pos][1] = self.cache[pos][1] + 1
                    # Reorder the cache by frequency
                    tmp_cache = self.cache
                    tmp_cache = self.reorder_cache_by_frequency(tmp_cache)
                    self.cache = tmp_cache
                elif replacement_policy == "LRFU": # TODO: develop LRFU policy
                    # LRFU is enabled
                    # Updated the CRF value of the flow
                    self.cache[pos][2] = self.cache[pos][2] + 1
                    # Reorder the cache by frequency
                    self.reorder_cache_by_frequency()
                else:
                    print("Please select LRU/LFU/LRFU")
                    exit(1)
                return True

        # The flow is not cached
        # replace the flow with designated policy
        if replacement_policy == "LRU":
            self.reorder_cache_by_recency(address, 1)
        elif replacement_policy == "LFU":
            self.cache[0][0] = address # Replace the least frequently used flow
            self.cache[0][1] = 1 # Initialize the frequency counter
            tmp_cache = self.cache
            tmp_cache = self.reorder_cache_by_frequency(tmp_cache)
            self.cache = tmp_cache
        elif replacement_policy == "LRFU":
            self.cache[0][0] = address # Replace the least frequently used flow
            self.cache[0][2] = 1 # Initialize the frequency counter
            self.reorder_cache_by_frequency()
        return False

    def simulate(self, cache_size, accesses, replacement_policy):
        print("== Fully associated cache ==")
        self.cache_init(cache_size)
        miss = 0
        for a in range(0, len(accesses)):
            # print(accesses[a])
            if self.access_cache(accesses[a], replacement_policy) == False:
                miss = miss + 1
        miss_rate = float(miss / float(len(accesses)))
        print("# of miss: {}\t # of access: {}".format(miss, len(accesses)))
        print("Miss rate: ", miss_rate)
        print("Hit rate: ", 1 - miss_rate)

    def setup(self, filepath):
        # global cacheList
        with open(filepath, 'r') as file:
            for line in file:
                temp = line.split('\n')[0]
                self.cacheList.append(temp)
