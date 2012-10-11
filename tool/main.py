"""
Run Dispersy in standalone mode.
"""

import optparse
import signal

from ..callback import Callback
from ..dispersy import Dispersy
from ..dprint import dprint
from ..endpoint import StandaloneEndpoint

def watchdog(dispersy):
    try:
        while True:
            yield 300.0
    except GeneratorExit:
        dispersy.endpoint.stop()

def start_script(opt):
    try:
        module, class_ = opt.script.strip().rsplit(".", 1)
        cls = getattr(__import__(module, fromlist=[class_]), class_)
    except Exception as exception:
        dprint(str(exception), exception=True, level="error")
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

    script = cls(**kargs)
    script.next_testcase()

def main(setup=None):
    assert setup is None or callable(setup)

    # define options
    command_line_parser = optparse.OptionParser()
    command_line_parser.add_option("--profiler", action="store_true", help="use cProfile on the Dispersy thread", default=False)
    command_line_parser.add_option("--memory-dump", action="store_true", help="use meliae to dump the memory periodically", default=False)
    command_line_parser.add_option("--statedir", action="store", type="string", help="Use an alternate statedir", default=u".")
    command_line_parser.add_option("--ip", action="store", type="string", default="0.0.0.0", help="Dispersy uses this ip")
    command_line_parser.add_option("--port", action="store", type="int", help="Dispersy uses this UDL port", default=12345)
    command_line_parser.add_option("--script", action="store", type="string", help="Script to execute, i.e. module.module.class", default="")
    command_line_parser.add_option("--kargs", action="store", type="string", help="Executes --script with these arguments.  Example 'startingtimestamp=1292333014,endingtimestamp=12923340000'")
    # # swift
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

    # setup
    callback = Callback()
    dispersy = Dispersy.get_instance(callback, unicode(opt.statedir))
    # if opt.swiftproc:
    #     from Tribler.Core.Swift.SwiftProcessMgr import SwiftProcessMgr
    #     sesslock = threading.Lock()
    #     spm = SwiftProcessMgr(opt.swiftpath, opt.swiftcmdlistenport, opt.swiftdlsperproc, sesslock)
    #     swift_process = spm.get_or_create_sp(opt.statedir)
    #     dispersy.endpoint = TunnelEndpoint(swift_process, dispersy)
    #     swift_process.add_download(dispersy.endpoint)
    # else:
    dispersy.endpoint = StandaloneEndpoint(dispersy, opt.port, opt.ip)
    dispersy.endpoint.start()

    # register tasks
    callback.register(watchdog, (dispersy,))
    callback.register(start_script, (opt,))

    def signal_handler(sig, frame):
        print "Received", sig, "signal in", frame
        dispersy.callback.stop(wait=False)
    signal.signal(signal.SIGINT, signal_handler)

    # start
    callback.loop()
    exit(1 if callback.exception else 0)
