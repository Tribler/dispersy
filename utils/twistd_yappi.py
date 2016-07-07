"""
This file contains code that can be used to install the yappi profiler in twistd plugins.
Importing this file is enough to register the yappi profiler in a twistd plugin.
"""

from twisted.application.app import _BasicProfiler, AppProfiler
from twisted.python.log import msg

try:
    import yappi
except ImportError:
    msg("Yappi not installed, profiling options won't be available")


class YappiProfileRunner(_BasicProfiler):
    """
    Runner for the Yappi profiler.
    """

    def run(self, reactor):
        """
        Run reactor under the Yappi profiler.
        """
        try:
            import yappi
        except ImportError as e:
            self._reportImportError("yappi", e)

        yappi.start(builtins=True)
        reactor.run()
        self.stop_profiler()

    def stop_profiler(self):
        """
        Stop the yappi profiler and write the data to a file
        """
        yappi.stop()
        msg("Yappi has shutdown")
        yappi_stats = yappi.get_func_stats()
        yappi_stats.sort("tsub")

        yappi_stats.save(self.profileOutput, type='callgrind')

        # Log the 50 most time consuming functions.
        count = 0
        for func_stat in yappi_stats:
            msg("YAPPI: %10dx  %10.3fs %s", func_stat.ncall, func_stat.tsub, func_stat.name)
            count += 1
            if count >= 50:
                break

AppProfiler.profilers['yappi'] = YappiProfileRunner
