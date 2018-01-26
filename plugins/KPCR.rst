
Windows maintains per-processor information for each physical CPU in the
system. This plugin displays this infomation.

### Sample output

..  code-block:: text

  win8.1.raw 21:15:09> kpcr
  -------------------> kpcr()
  **************************************************
  Property                       Value
  ------------------------------ -----
  Offset (V)                     0xf802d3307000
  KdVersionBlock                 Pointer to -
  IDT                            0xf802d4a43080
  GDT                            0xf802d4a43000
  CurrentThread                 : 0xe00001254440 TID 3420 (winpmem_1.5.2.:2628)
  IdleThread                    : 0xf802d335fa80 TID 0 (System:0)
  Details                       : CPU 0 (GenuineIntel @ 2517 MHz)
  CR3/DTB                       : 0x1a7000


