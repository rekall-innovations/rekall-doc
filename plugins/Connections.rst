
Prior to Windows 7, the windows TCP/IP stack uses objects of type _TCP_OBJECT to
track TCP endpoints. These are the objects parsed by this module, hence this
module will only be available on images from windows XP.

This module walks the _TCP_OBJECT hash tables and displays information related
to the TCP endpoints.

### Notes

1. This plugin depends on exported debugging symbols, and therefore requires the
   correct tcpip profile to be loaded from the profile repository. See the
   [FAQ](/faq.html#profile) if you need to generate a profile.

2. For later versions of windows use the [netscan](Netscan.html) or the
   [netstat](Netstat.html) modules.

### Sample output

..  code-block:: text

  xp-laptop-2005-06-25.img 23:00:24> connections
  ---------------------------------> connections()
  Offset (V) Local Address             Remote Address               Pid
  ---------- ------------------------- ------------------------- ------
  0x820869b0 127.0.0.1:1055            127.0.0.1:1056              2160
  0xffa2baf0 127.0.0.1:1056            127.0.0.1:1055              2160
  0x8220c008 192.168.2.7:1077          64.62.243.144:80            2392
  0x81f11e70 192.168.2.7:1082          205.161.7.134:80            2392
  0x8220d6b8 192.168.2.7:1066          199.239.137.200:80          2392



