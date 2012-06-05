#!/usr/bin/python
"""

Concerning the relative imports, from PEP 328:
http://www.python.org/dev/peps/pep-0328/

   Relative imports use a module's __name__ attribute to determine that module's position in the
   package hierarchy. If the module's name does not contain any package information (e.g. it is set
   to '__main__') then relative imports are resolved as if the module were a top level module,
   regardless of where the module is actually located on the file system.
"""

from dispersy.tool.main import main
from dispersy.tool.callbackscript import DispersyCallbackScript
from dispersy.script import DispersyClassificationScript, DispersyTimelineScript, DispersyDestroyCommunityScript, DispersyBatchScript, DispersySyncScript, DispersyIdenticalPayloadScript, DispersySubjectiveSetScript, DispersySignatureScript, DispersyMemberTagScript, DispersyMissingMessageScript, DispersyUndoScript, DispersyCryptoScript, DispersyDynamicSettings, DispersyBootstrapServers, DispersyBootstrapServersStresstest

def testcases(dispersy, script):
    script.add("dispersy-batch", DispersyBatchScript)
    script.add("dispersy-classification", DispersyClassificationScript)
    script.add("dispersy-crypto", DispersyCryptoScript)
    script.add("dispersy-destroy-community", DispersyDestroyCommunityScript)
    script.add("dispersy-dynamic-settings", DispersyDynamicSettings)
    script.add("dispersy-identical-payload", DispersyIdenticalPayloadScript)
    script.add("dispersy-member-tag", DispersyMemberTagScript)
    script.add("dispersy-missing-message", DispersyMissingMessageScript)
    script.add("dispersy-signature", DispersySignatureScript)
    script.add("dispersy-subjective-set", DispersySubjectiveSetScript)
    script.add("dispersy-sync", DispersySyncScript)
    script.add("dispersy-timeline", DispersyTimelineScript)
    script.add("dispersy-undo", DispersyUndoScript)
    script.add("dispersy-bootstrap-servers", DispersyBootstrapServers)
    script.add("dispersy-bootstrap-servers-stresstest", DispersyBootstrapServersStresstest)
    script.add("dispersy-callback", DispersyCallbackScript)

if __name__ == "__main__":
    main(ready=testcases)
