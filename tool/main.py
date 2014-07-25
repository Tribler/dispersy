"""
Run Dispersy in standalone mode.
"""
import logging
import optparse  # deprecated since python 2.7
import os
import signal

from twisted.internet import reactor
from twisted.python.log import addObserver

from ..dispersy import Dispersy
from ..endpoint import StandaloneEndpoint


# use logger.conf if it exists
if os.path.exists("logger.conf"):
    # will raise an exception when logger.conf is malformed
    logging.config.fileConfig("logger.conf")
# fallback to basic configuration when needed
logging.basicConfig(format="%(asctime)-15s [%(levelname)s] %(message)s")

logger = logging.getLogger(__name__)


def start_script(dispersy, opt):
    try:
        module, class_ = opt.script.strip().rsplit(".", 1)
        cls = getattr(__import__(module, fromlist=[class_]), class_)
    except Exception as exception:
        logger.exception("%s", exception)
        raise SystemExit(str(exception), "Invalid --script", opt.script)

    try:
        kargs = {}
        if opt.kargs:
            for karg in opt.kargs.split(","):
                if "=" in karg:
                    key, value = karg.split("=", 1)
                    kargs[key.strip()] = value.strip()
    except:
        raise SystemExit("Invalid --kargs", opt.kargs)

    script = cls(dispersy, **kargs)
    script.next_testcase()


def main_real(setup=None):
    assert setup is None or callable(setup)

    # define options
    command_line_parser = optparse.OptionParser()
    command_line_parser.add_option("--profiler", action="store_true", help="use cProfile on the Dispersy thread", default=False)
    command_line_parser.add_option("--memory-dump", action="store_true", help="use meliae to dump the memory periodically", default=False)
    command_line_parser.add_option("--databasefile", action="store", help="use an alternate databasefile", default=u"dispersy.db")
    command_line_parser.add_option("--statedir", action="store", type="string", help="Use an alternate statedir", default=u".")
    command_line_parser.add_option("--ip", action="store", type="string", default="0.0.0.0", help="Dispersy uses this ip")
    command_line_parser.add_option("--port", action="store", type="int", help="Dispersy uses this UDL port", default=12345)
    command_line_parser.add_option("--script", action="store", type="string", help="Script to execute, i.e. module.module.class", default="")
    command_line_parser.add_option("--kargs", action="store", type="string", help="Executes --script with these arguments.  Example 'startingtimestamp=1292333014,endingtimestamp=12923340000'")
    command_line_parser.add_option("--debugstatistics", action="store_true", help="turn on debug statistics", default=False)
    command_line_parser.add_option("--strict", action="store_true", help="Exit on any exception", default=False)
    # swift
    # command_line_parser.add_option("--swiftproc", action="store_true", help="Use swift to tunnel all traffic", default=False)
    # command_line_parser.add_option("--swiftpath", action="store", type="string", default="./swift")
    # command_line_parser.add_option("--swiftcmdlistenport", action="store", type="int", default=7760+481)
    # command_line_parser.add_option("--swiftdlsperproc", action="store", type="int", default=1000)
    if setup:
        setup(command_line_parser)

    # parse command-line arguments
    opt, args = command_line_parser.parse_args()
    if not opt.script:
        command_line_parser.print_help()
        exit(1)

    if opt.strict:
        from ..util import unhandled_error_observer
        addObserver(unhandled_error_observer)

    # setup
    dispersy = Dispersy(StandaloneEndpoint(opt.port, opt.ip), unicode(opt.statedir), unicode(opt.databasefile))
    dispersy.statistics.enable_debug_statistics(opt.debugstatistics)

    def signal_handler(sig, frame):
        logger.warning("Received signal '%s' in %s (shutting down)", sig, frame)
        dispersy.stop()
        reactor.stop()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # start
    if not dispersy.start():
        raise RuntimeError("Unable to start Dispersy")

    # This has to be scheduled _after_ starting dispersy so the DB is opened by when this is actually executed.
    # register tasks
    reactor.callLater(0, start_script, dispersy, opt)


def main(setup=None):
    reactor.exitCode = 0
    reactor.callWhenRunning(setup)
    # start the reactor
    reactor.run()
    exit(reactor.exitCode)
