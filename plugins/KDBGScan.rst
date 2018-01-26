
Windows keeps a store of some useful global variables in a structure called
**_KDDEBUGGER_DATA64**. This information is used by the microsoft kernel
debugger in order to bootstap the analysis of a crash dump.

Rekall no longer uses the Kernel Debugger Block for analysis - instead accurate
global symbol information are fetched from Microsoft PDB files containing
debugging symbols.

### Notes

1. Previous versions of Rekall used the KDBG heavily for analysis, and by
   extension used this plugin. Currently the KDBG is not used by Rekall at all
   so this plugin is not all that useful.

