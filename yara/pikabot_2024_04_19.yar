import "pe"
rule MAL_WIN_trojan_pikabot
{
    meta:
        description = "Detects Pikabot malware"
        author="James Jolley"
        date="2024-04-19"
        filename="QHFileSmasher.exe"
        hash="7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"
    strings:
        $r1 = /\d{1,2}=\w{4,7}Match\|\w{0,}\|(\w{0,}\\{0,}){0,}\.{0,}\w{0,3}(\\{0,}\.{0,}){0,}/ wide
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1500KB and 
        pe.pdb_path contains "QHFileSmasher.pdb" and 
        pe.version_info["InternalName"] contains "QHFileSmasher" and  
        #r1 >= 5
}


