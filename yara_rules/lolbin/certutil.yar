import "pe"

rule LOLBIN_Certutil_Download
{
    meta:
        description = "Certutil abused to download payloads"
        author = "Infra DFIR"
        scope = "lolbin/certutil"
    strings:
        $certutil = "certutil.exe" ascii wide nocase
        $urlcache = "-urlcache" ascii wide nocase
        $split = "-split" ascii wide nocase
        $http = "http" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $certutil and $urlcache and $split and $http
}
