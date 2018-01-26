
This plugin dumps the mapped PE files associated with a windows process. It is
equivalent to calling **pedump** with an image base corresponding to the VAD
section of the main process executable.

The **procdump** plugin is a thin wrapper around the **pedump** plugin.

### Sample output

..  code-block:: text

  win7.elf 14:42:55> procdump proc_regex="csrss", dump_dir="/tmp/"
  **************************************************
  Dumping csrss.exe, pid: 348    output: executable.csrss_exe_348.exe
  **************************************************
  Dumping csrss.exe, pid: 396    output: executable.csrss_exe_396.exe


