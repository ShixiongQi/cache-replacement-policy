import sys, time
import hashlib
import scapy
from scapy.all import *
from scapy.utils import PcapReader

class cacheSim(object):
    def __init__(self):
        self.cache = [] # Flow Director
        self.cacheList = [] # The cache list

        # LRFU parameters
        self.factor_lambda = 1
        self.base = 0.5 ** self.factor_lambda
        self.time = 0

    def cache_init(self, size):
        self.cache.clear()
        for i in range(0, size):
            tmp = [0,0,[0,0]] # [IP 5Tuples],[frequency_counter | current CRF value],[last CRF value, last timestamp]
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

    # def reorder_cache_by_recency_frequency(self, _cache, pos): # O(nlogn)
    #     for i in range(pos, len(_cache) - 1):
    #         for j in range(len(_cache) - i - 1):
    #             if _cache[j][1] > _cache[j+1][1]:
    #                 _cache[j], _cache[j+1] = _cache[j+1], _cache[j]
    #     return _cache

    def reorder_cache_by_recency_frequency(self, _cache, pos): # O(nlogn)
        for i in range(pos, len(_cache) - 1):
            for j in range(len(_cache) - i - 1):
                if _cache[j][1] * self.weighting_func(self.time - _cache[j][2][1]) > _cache[j+1][1] * self.weighting_func(self.time - _cache[j+1][2][1]):
                    _cache[j], _cache[j+1] = _cache[j+1], _cache[j]
        return _cache

    def weighting_func(self, x): # (1/p)^(lambda * x)
        return self.base ** x

    def access_cache(self, address, replacement_policy):

        for pos in range(0, len(self.cache)):
            if self.cache[pos][0] == address:
                # print("match@[{}]\n".format(pos))
                # The flow is cached, Update the metadata of the flow
                if replacement_policy == "LRU":
                    # LRU is enabled, Reorder the cache by recency
                    self.reorder_cache_by_recency(address, pos + 1)

                elif replacement_policy == "LFU":
                    # LFU is enabled, Update the frequency counter of the flow
                    self.cache[pos][1] = self.cache[pos][1] + 1
                    # Reorder the cache by frequency
                    tmp_cache = self.cache
                    tmp_cache = self.reorder_cache_by_frequency(tmp_cache)
                    self.cache = tmp_cache

                elif replacement_policy == "LRFU":
                    # LRFU is enabled, Updated the CRF value of the flow
                    self.cache[pos][2][0] = self.cache[pos][1]
                    tmp_cur_time = self.time
                    delta_t = tmp_cur_time - self.cache[pos][2][1]
                    # print(delta_t)
                    # print(self.weighting_func(delta_t))
                    self.cache[pos][1] = 1 + self.weighting_func(delta_t) * self.cache[pos][2][0]
                    # print(self.weighting_func(delta_t) * self.cache[pos][2][0])
                    self.cache[pos][2][1] = tmp_cur_time

                    # Reorder the cache by CRF
                    tmp_cache = self.cache
                    tmp_cache = self.reorder_cache_by_recency_frequency(tmp_cache, pos)
                    self.cache = tmp_cache

                else:
                    print("Please select LRU/LFU/LRFU")
                    exit(1)
                return True

        # The flow is not cached, replace the flow with designated policy
        if replacement_policy == "LRU":
            self.reorder_cache_by_recency(address, 1)

        elif replacement_policy == "LFU":
            self.cache[0][0] = address # Replace the least frequently used flow
            self.cache[0][1] = 1 # Initialize the frequency counter

            tmp_cache = self.cache
            tmp_cache = self.reorder_cache_by_frequency(tmp_cache)
            self.cache = tmp_cache

        elif replacement_policy == "LRFU":
            self.cache[0][0] = address # Replace the least CRF flow
            self.cache[0][1] = 1 # Initialize the CRF value
            self.cache[0][2][0] = 0 # Setup [last CRF, last timestamp]
            self.cache[0][2][1] = self.time

            tmp_cache = self.cache
            tmp_cache = self.reorder_cache_by_recency_frequency(tmp_cache,0)
            self.cache = tmp_cache
        else:
            print("Please select LRU/LFU/LRFU")
            exit(1)
        return False

    def print_cache(self, xx):
        for i in range(len(xx)):
            print("#-{}-#[{:.2f}, [{:.2f}, {:.2f}]] ".format(i,xx[i][1], xx[i][2][0], xx[i][2][1]), end='', flush=True)
        print()

    def simulate(self, cache_size, accesses, replacement_policy):
        print("== Fully associated cache ==")
        self.cache_init(cache_size)
        miss = 0
        for a in range(0, len(accesses)):
            # print(accesses[a])
            # print(self.cache)
            # tmp = self.cache
            # self.print_cache(tmp)
            # input("Enter")
            if self.access_cache(accesses[a], replacement_policy) == False:
                miss = miss + 1
            self.time = self.time + 1
        miss_rate = float(miss / float(len(accesses)))
        print("# of miss: {}\t # of access: {}".format(miss, len(accesses)))
        print("Miss rate: ", miss_rate)
        print("Hit rate: ", 1 - miss_rate)

    def setup(self, filepath):
        with open(filepath, 'r') as file:
            for line in file:
                temp = line.split('\n')[0]
                self.cacheList.append(int(temp, 16))
