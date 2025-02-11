rule MAL_WIN_trojan_darkgate
{
    meta:
        description = "Detects Darkgate trojan"
        author="James Jolley"
        date="2024-04-15"
        filename="filactery.exe"
        hash="0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23"
    strings:
        $s1 = "C:\\Users\\Alex\\Documents\\repos\\repos\\t34_new\\users\\MAGA\\cryptbase_meow\\x64\\Release\\cryptbase.pdb"
        $s2 = "C:\\Users\\Alex\\Documents\\repos\\repos\\t34_new\\users\\my\\selfupdate\\Dropper\\wldp\\x64\\Release\\wldp.pdb"
        $s3 = "[AntiDebug] [dll_check()] [ERROR]: Virtual Machine Detected: VMWare: from "
        $r1 = /C:\\Windows\\system32\\cryptbase\.SystemFunction\d{3}/
        $r2 = /C:\\Windows\\system32\\wldp\.Wldp\w*/
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1300KB and
        #r1 >= 8  and #r2 >= 4 and all of ($s*)
}