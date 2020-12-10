import sys
from cacheSim.lru2q import lru2q

# if __name__ == "__main__":
filename = str(sys.argv[1])
cache_size = int(sys.argv[2])
buffer_size = int(sys.argv[3])
max_trace_size = 99971

csim = lru2q()

if cache_size <= max_trace_size and buffer_size < cache_size:
    csim.setup(filename) # import trace file
    csim.simulate(cache_size, buffer_size) # run the replacement policy
else:
    print("Trace size is less than the cache size")
    exit(1)
