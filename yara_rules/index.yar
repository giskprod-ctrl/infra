// Main entry point for all YARA rules bundled with the triage toolkit.
// Individual categories maintain their own index files that are included here.

include "malware/index.yar"
include "lolbin/index.yar"
include "internal/index.yar"
include "vendor/index.yar"
