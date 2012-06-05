"""
Run Dispersy in standalone mode.
"""

import optparse

from ..script import Script
from ..callback import Callback
from ..dispersy import Dispersy
from ..endpoint import StandaloneEndpoint

def watchdog(dispersy):
    try:
        while True:
            yield 300.0
    except GeneratorExit:
        dispersy.endpoint.stop()

def main(setup=None, ready=None):
    assert setup is None or callable(setup)
    assert ready is None or callable(ready)

    # define options
    command_line_parser = optparse.OptionParser()
    command_line_parser.add_option("--statedir", action="store", type="string", help="Use an alternate statedir", default=u".")
    command_line_parser.add_option("--ip", action="store", type="string", default="0.0.0.0", help="Dispersy uses this ip")
    command_line_parser.add_option("--port", action="store", type="int", help="Dispersy uses this UDL port", default=12345)
    command_line_parser.add_option("--script", action="store", type="string", help="Runs the Script python file with <SCRIPT> as an argument", default="")
    command_line_parser.add_option("--script-kargs", action="store", type="string", help="Executes --script with these arguments.  Example 'startingtimestamp=1292333014,endingtimestamp=12923340000'")
    # # swift
    # command_line_parser.add_option("--swiftproc", action="store_true", help="Use swift to tunnel all traffic", default=False)
    # command_line_parser.add_option("--swiftpath", action="store", type="string", default="./swift")
    # command_line_parser.add_option("--swiftcmdlistenport", action="store", type="int", default=7760+481)
    # command_line_parser.add_option("--swiftdlsperproc", action="store", type="int", default=1000)
    if callable(setup):
        setup(command_line_parser)

    # parse command-line arguments
    opt, _ = command_line_parser.parse_args()
    print "Press Ctrl-C to stop Dispersy"

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

    # scripts
    script_kargs = {}
    if opt.script_kargs:
        for arg in opt.script_args.split(","):
            key, value = arg.split("=")
            script_kargs[key] = value
    script = Script.get_instance(callback, script_kargs)

    # register tasks
    callback.register(watchdog, (dispersy,))
    if callable(ready):
        callback.register(ready, (dispersy, script))
    callback.register(script.load, (opt.script,))

    # start
    callback.loop()
    return callback.exception

#             if opt.enable_allchannel_script:
#                 # from Tribler.Community.allchannel.script import AllChannelScript
#                 # script.add("allchannel", AllChannelScript, include_with_all=False)

#                 from Tribler.community.allchannel.script import AllChannelScenarioScript
#                 script.add("allchannel-scenario", AllChannelScenarioScript, script_kargs, include_with_all=False)

#             if opt.enable_walktest_script:
#                 from Tribler.community.walktest.script import ScenarioScript
#                 script.add("walktest-scenario", ScenarioScript, script_kargs, include_with_all=False)

#             if opt.enable_ycsb_script:
#                 from Tribler.community.ycsb.script import YCSBScript
#                 script.add("ycsb-scenario", YCSBScript, script_kargs, include_with_all=False)

#             if opt.enable_demers_script:
#                 from Tribler.community.demerstest.script import DemersScript
#                 script.add("demers-scenario", DemersScript, script_kargs, include_with_all=False)

#             if opt.enable_udp_script:
#                 from script import DispersyUDPScript
#                 script.add("udp-scenario", DispersyUDPScript, script_kargs, include_with_all=False)
