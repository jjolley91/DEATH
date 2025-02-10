import "pe"

rule MAL_WIN_Matanbuhchus_Loader_PE
{
    meta:
        description = "Detects Matanbuhchus masquerading as a CPL file"
        author="James Jolley"
        date="2024-04-09"
        reference="https://github.com/pr0xylife/Matanbuchus/blob/main/Matanbuchus_07.03_2024.txt"
        hash="1ca1315f03f4d1bca5867ad1c7a661033c49bbb16c4b84bea72caa9bc36bd98b"
    strings:
        $s1= "DllRegisterServer"
        $s2= "DllUnregisterServer"
        $s3= "_RegisterDll@12"
        $s4= "_UnregisterDll@4"
        $s5= "EmulateCallWaiting"
        $s6= "AppPolicyGetProcessTerminationMethod"
        $s7= "** GET_MSG_BODY **" wide
        $s8= "Receiver - Got NAK" wide
        $s9= "Start Monitoring A" wide
        $s10= "operator<=>" fullword
        $s11= "MohOverrideActionF"wide
        $s12= "ModemMonitor(RKMON"wide
        $s13= "** GET_CHECKSUM **"
        $s14= "** CHOSEN_DATA_PUM"
        $s15= "operator co_await"
        $s16= "** StartIdle **"
        $s17= "win32.DLL" fullword
    condition:
        pe.is_pe and 
        filesize < 750KB and
        pe.imports("KERNEL32.dll","IsDebuggerPresent") and
        pe.exports("DllRegisterServer") and
        all of ($s*)
}


