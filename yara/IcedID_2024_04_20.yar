 rule MAL_WIN_trojan_icedid
{
    meta:
        description = "Detects IcedID malware"
        author="James Jolley"
        date="April 2024"
        filename="cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc.exe"
        hash="cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc"
    strings:
        $s1 = "Prevents the user from cancelling during the installation process."wide
        $s2 = "/SUPPRESSMSGBOXES"wide
        $s3 = "/NOCANCEL" wide
        $s4 = "Freemake Video Converter"wide
        $r1 = /(http(s){0,1}:\/\/){1}(cacerts|crl\d{1}|ocsp|www\.{0,1}){1}(\.digicert\.com{0,1}|avast\.com)(\w{0,}\/{0,}-{0,1}\.{0,1}){0,}/
    condition:
        uint16(0) == 0x5a4d and
        filesize < 4200KB and
        #r1 >= 4 and any of ($s*)
}