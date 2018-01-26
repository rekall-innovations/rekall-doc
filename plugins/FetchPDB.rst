
The Microsoft Visual Studio compiler stores debugging information for each
binary built in a PDB file. Each binary contains a unique GUID which can be used
to fetch the correct PDB file from the public Microsoft symbol server.

The `fetch_pdb` plugin is used to fetch the correct PDB file from the symbol
server. You will need to provide the name of the PDB file and the GUID - both of
these are found from the PE headers of the binary.

Note that this plugin is mainly used by the `build_local_profile` plugin and by
the `manage_repo` plugins, but might also be useful on its own. Usually you need
to `parse_pdb` after fetching it so a profile can be generated for Rekall to
use.

In the example below we find the GUID and pdb file name of an executable from
the image, then use the `fetch_pdb` plugin to fetch it. Note that PDB files are compressed using CAB on the symbol server so we need `cabextract` installed locally.

..  code-block:: text

  [1] win7.elf 23:08:40> peinfo "termdd"
            Attribute                                       Value
  ------------------------------ ------------------------------------------------------------
  Machine                        IMAGE_FILE_MACHINE_AMD64
  TimeDateStamp                  2009-07-14 00:16:36Z
  Characteristics                IMAGE_FILE_DLL, IMAGE_FILE_EXECUTABLE_IMAGE,
                                 IMAGE_FILE_LARGE_ADDRESS_AWARE
  GUID/Age                       2A530717E88549BB92DBB72C224EC2B11
  PDB                            termdd.pdb
  MajorOperatingSystemVersion    6
  MinorOperatingSystemVersion    1
  MajorImageVersion              6
  
  ....
  
  [1] win7.elf 23:09:12> fetch_pdb pdb_filename="termdd.pdb", guid="2A530717E88549BB92DBB72C224EC2B11"
   Trying to fetch http://msdl.microsoft.com/download/symbols/termdd.pdb/2A530717E88549BB92DBB72C224EC2B11/termdd.pd_
   Trying to fetch http://msdl.microsoft.com/download/symbols/termdd.pdb/2A530717E88549BB92DBB72C224EC2B11/termdd.pd_
  Extracting cabinet: /tmp/tmpXkEgyu/termdd.pd_
    extracting termdd.pdb
  
  All done, no errors.



