import sys
from cacheSim.cacheSim import cacheSim

# if __name__ == "__main__":
filename = str(sys.argv[1])
cache_size = int(sys.argv[2])
replacement_policy = str(sys.argv[3]) # LRU LFU LRFU
max_trace_size = 99971

csim = cacheSim()

if cache_size <= max_trace_size:
    csim.setup(filename) # import trace file
    accesses = csim.cacheList
    csim.simulate(cache_size, accesses, replacement_policy) # run the replacement policy
else:
    print("Trace size is less than the cache size")
    exit(1)
