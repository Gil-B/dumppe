DumpPE is a WinDBG extension that dumps PE files from memory.<br>
It contains two commands:<br>
!dumppe.dump_raw - dumps a PE file from memory to disk as-is (the result will be a PE file as it appears in memory (after relocations, things will be located where they should be based on RVAs, etc.)<br>
<br>
!dumppe.dump_disk - dumps a PE file from memory to disk and attempts to write it as it was before being loaded - therefore making it a valid PE that can be loaded again at will.