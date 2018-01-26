
Rekall uses debugging symbols to analyze memory. Each time Microsoft compilers
generate a binary (executable or DLL) they also emit debugging information in a
separate PDB file. Rekall needs a profile for each binary of interest (A
profile is a JSON file containing important debugging information about the
binary).

Use the `fetch_pdb` plugin to fetch the PDB file and the `parse_pdb` plugin to
parse it and produce a JSON file for Rekall to use.

Note that normally this plugin is called by other plugins such as
`build_local_profile` or automatically by Rekall. So users do not need to call
this plugin directly in most cases.

..  code-block:: text

  [1] win7.elf 23:09:12> fetch_pdb pdb_filename="termdd.pdb", guid="2A530717E88549BB92DBB72C224EC2B11"
   Trying to fetch http://msdl.microsoft.com/download/symbols/termdd.pdb/2A530717E88549BB92DBB72C224EC2B11/termdd.pd_
   Trying to fetch http://msdl.microsoft.com/download/symbols/termdd.pdb/2A530717E88549BB92DBB72C224EC2B11/termdd.pd_
  Extracting cabinet: /tmp/tmpXkEgyu/termdd.pd_
    extracting termdd.pdb
  
  All done, no errors.
  [1] win7.elf 23:55:07> parse_pdb pdb_filename="termdd.pdb", output_filename="termdd.json"
                 Out<59> Plugin: parse_pdb
  [1] win7.elf 23:55:37> !head termdd.json
  {
   "$CONSTANTS": {
    "ExEventObjectType": 41408,
    "Globals": 46144,
    "HotPatchBuffer": 45056,
    "IcaChannelDispatchTable": 45856,
    "IcaChargeForPostCompressionUsage": 46106,
    "IcaConnectionDispatchTable": 45632,
    "IcaDeviceObject": 46848,
    "IcaDisableFlowControl": 46105,



