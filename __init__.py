import gc
import sys

from threading import Timer

# Setup hourly garbage collection (and stats printing)

def _gc_collect():
    # shows all the memleak info and stores
    # uncollectable objects to gc.garbage
    gc.set_debug(gc.DEBUG_LEAK)
    gc.collect()
    sys.stderr.write("\n-- DUMP BEGIN --\n")
    sys.stderr.write("Uncollectable objects:\n")
    sys.stderr.write("%s\n" % (gc.garbage,))
    sys.stderr.write("\n-- DUMP END --\n")
    gc.set_debug(False)
    # now clear for real
    del gc.garbage[:]
    gc.collect()
    _setup_timer()

def _setup_timer():
    timer = Timer(3600, _gc_collect)
    timer.name = "HourlyGarbageCollector"
    timer.daemon = True
    timer.start()

_setup_timer()
