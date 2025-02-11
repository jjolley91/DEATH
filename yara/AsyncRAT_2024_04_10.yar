rule MAL_WIN_RAT_async
{
meta:
description = "Detects Windows AsyncRAT malware"
author="James Jolley"
date="2024-04-10"
reference = "https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/asyncrat"
hash="8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"
strings:
 $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn " wide
 $s2 = "vmware" wide
 $s3 = "VirtualBox" wide
 $s4 = "Stub.exe" wide
 $s5 = "\nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS" wide
 $s6 = "anydesk" wide
 $s7 = "EH35w5pUEA3EHiw371lacW9TesiqE9bQ" base64wide
 $s8 = "ABRIL.exe"
 $s9 = "Bitcoin" wide
 $s10 = "AntivirusProduct" wide
condition:
uint16(0) == 0x5a4d and
filesize < 100KB and
all of ($s*)
}