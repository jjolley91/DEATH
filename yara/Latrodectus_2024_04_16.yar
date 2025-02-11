rule MAL_WIN_trojan_Latrodectus
{
    meta:
        description = "Detects the Latrodectus trojan"
        author="James Jolley"
        date="2024-04-16"
        filename="TRUFOS.DLL"
        hash="aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
    strings:
        $s1 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" wide
        $s2 = "Bitdefender" wide
        $r1 = /\w:\\\w{0,}\\ARK23181_2\\(\w{0,}\\){0,}\w{0,}\.\w{0,}/
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1000KB and
        #r1 >= 4 and all of ($s*)
}