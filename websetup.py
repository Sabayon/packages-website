"""Setup the www application"""
import logging

from paste.deploy import appconfig
from pylons import config

from www.config.environment import load_environment

log = logging.getLogger(__name__)

import gc
import sys
import signal

gc.set_debug(gc.DEBUG_STATS)
# Run gc.collect() with stats to stderr on SIGUSR2
def _gc_collect(signum, frame):
    # shows all the memleak info and stores
    # uncollectable objects to gc.garbage
    gc.set_debug(gc.DEBUG_LEAK)
    gc.collect()
    sys.stderr.write("Uncollectable objects:\n")
    sys.stderr.write("%s\n" % (gc.garbage,))
    sys.stderr.write("\n---\n")
    gc.set_debug(gc.DEBUG_STATS)
    # now clear for real
    del gc.garbage[:]
    gc.collect()

signal.signal(signal.SIGUSR2, _gc_collect)

def setup_config(command, filename, section, vars):
    """Place any commands to setup www here"""
    conf = appconfig('config:' + filename)
    load_environment(conf.global_conf, conf.local_conf)
