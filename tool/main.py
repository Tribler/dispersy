"""
Run Dispersy in standalone mode.
"""

# optparse is deprecated since python 2.7
import optparse
import signal

from ..dispersy import Dispersy
from ..endpoint import StandaloneEndpoint
from ..logger import get_logger, get_context_filter
from .mainthreadcallback import MainThreadCallback
logger = get_logger(__name__)


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
    context_filter = get_context_filter()

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
    command_line_parser.add_option("--log-identifier", type="string", help="this 'identifier' key is included in each log entry (i.e. it can be used in the logger format string)", default=context_filter.identifier)
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

    # set the log identifier
    context_filter.identifier = opt.log_identifier

    # setup callback
    def exception_handler(exception, fatal):
        logger.error("An exception occurred.  Quitting because we are running with --strict enabled.")
        # return fatal=True
        return True
    callback = MainThreadCallback("Dispersy")
    if opt.strict:
        callback.attach_exception_handler(exception_handler)

    # setup
    dispersy = Dispersy(callback, StandaloneEndpoint(opt.port, opt.ip), unicode(opt.statedir), unicode(opt.databasefile))
    dispersy.statistics.enable_debug_statistics(opt.debugstatistics)

    # if opt.swiftproc:
    #     from Tribler.Core.Swift.SwiftProcessMgr import SwiftProcessMgr
    #     sesslock = threading.Lock()
    #     spm = SwiftProcessMgr(opt.swiftpath, opt.swiftcmdlistenport, opt.swiftdlsperproc, sesslock)
    #     swift_process = spm.get_or_create_sp(opt.statedir)
    #     dispersy.endpoint = TunnelEndpoint(swift_process, dispersy)
    #     swift_process.add_download(dispersy.endpoint)
    # else:

    # register tasks
    callback.register(start_script, (dispersy, opt))

    def signal_handler(sig, frame):
        logger.warning("Received signal '%s' in %s (shutting down)", sig, frame)
        dispersy.stop(timeout=0.0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # start
    if not dispersy.start():
        raise RuntimeError("Unable to start Dispersy")

    # wait forever
    callback.loop()
    return callback


def main(setup=None):
    callback = main_real(setup)
    exit(1 if callback.exception else 0)
