

The PFN database can be used to resolve a physical address to its virtual
address in the process address space. Since processes must have unique page
tables, and therefore a unique DTB, we can enumerate all unique page tables on
the system.

Using this technique allows us to locate hidden processes. We simply check each
physical page and locate its DTB (or page table directory base) offset. We then
match the DTB to a known process DTB. If the DTB is not known this is a strong
indication that the process is hidden.

### Sample output

..  code-block:: text

  win8.1.raw 16:23:50> dtbscan
  -------------------> dtbscan()
       DTB           VAddr        _EPROCESS    Image Name           Known
  -------------- -------------- -------------- -------------------- -----
  0x0000001a7000 0xf6fb7dbed000 0xe00000074580 System               True
  0x0000118a3000 0xf6fb7dbed000 0xe00002073900 explorer.exe         True
  0x00000923e000 0xf6fb7dbed000 0xe000020ea900 svchost.exe          True
  0x000036ea3000 0xf6fb7dbed000 0xe000006208c0 taskhost.exe         True
  0x000004c01000 0xf6fb7dbed000 0xe000000ce080 wininit.exe          True
  0x00000d0a4000 0xf6fb7dbed000 0xe000022c6900 MsMpEng.exe          True
  0x0000093c4000 0xf6fb7dbed000 0xe000020df080 svchost.exe          True
  0x0000348c6000 0xf6fb7dbed000 0xe00001e2f700 dwm.exe              True
  0x000011504000 0xf6fb7dbed000 0xe000007a3080 svchost.exe          True
  0x000007c94000 0xf6fb7dbed000 0xe00001f22080 cmd.exe              True
  0x00002fe03000 0xf6fb7dbed000 0xe00002043900 conhost.exe          True
  0x00002f8ce000 0xf6fb7dbed000 0xe00001299900 SearchIndexer.       True
  0x0000207b9000 0xf6fb7dbed000 0xe00002645080 VBoxTray.exe         True


