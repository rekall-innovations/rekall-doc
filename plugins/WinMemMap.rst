
To enumerate the address space of a process use this plugin.

It is not that useful in practice, unless you want to manually translate a
physical address to a virtual address.

### Notes

1. It is not often necessary to dump the entire page tables of each
   process. Instead it is possible to first switch to the process context (using
   the **cc** plugin), and then use *vtop* to translate the virtual address to
   physical address.

2. Similar to the **memdump** plugin, we do not dump the kernel address space
   portion for processes unless the **all** parameter is specified.

### Sample output

..  code-block:: text

  win7.elf 00:54:22> memmap pid=2912
  -----------------> memmap(pid=2912)
  **************************************************
  Process: 'vol.exe' pid: 2912
  
  Dumping address space at DTB 0x271ec000
  
     Virtual        Physical         Size
  -------------- -------------- --------------
  0x000000010000 0x000007c4c000         0x1000
  0x000000020000 0x00000818f000         0x1000
  0x000000021000 0x000007e11000         0x1000
  0x00000002f000 0x000008010000         0x1000
  0x000000040000 0x00002428e000         0x1000
  0x000000050000 0x000001e6b000         0x1000
  0x000000051000 0x000007f49000         0x1000


