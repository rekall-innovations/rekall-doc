
To extract a kernel module from memory and dump it to disk for analysis, use the
moddump command. A regular expression can be specified for the module name to
dump.

### Note

1. In order to dump any PE file from memory we need the PE header to be memory
   resident. Often this is not the case, and the header is flushed out of
   virtual memory.

2. When dumping any binary from memory, it is not usually a perfect binary
   (i.e. you can not just run it). This is because the Import Address Table
   (IAT) reflects the patched version in memory and some pages may be
   missing. The resultant binary is probably only useful to analyses using a
   tool like IDA pro.


### Sample output

In this example we dump the winpmem driver to disk. The winpmem driver loads
from a temporary file name (You can see it using the [modules](Modules.html)
plugin.

..  code-block:: text

  win8.1.raw 23:27:12> moddump regex="tmp", dump_dir="/tmp"
  -------------------> moddump(regex="tmp", dump_dir="/tmp")
  Dumping pmeA86F.tmp, Base: f800025ca000 output: driver.f800025ca000.sys


