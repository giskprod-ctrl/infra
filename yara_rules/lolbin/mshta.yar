import "pe"

rule LOLBIN_Mshta_RemoteScript
{
    meta:
        description = "MSHTA executing remote HTA script"
        author = "Infra DFIR"
        scope = "lolbin/mshta"
    strings:
        $mshta = "mshta" ascii wide nocase
        $http = "http" ascii wide nocase
        $exec = "Execute" ascii wide nocase
        $vbscript = "vbscript" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $mshta and $http and ($exec or $vbscript)
}

rule LOLBIN_Mshta_ComObjectAbuse
{
    meta:
        description = "MSHTA leveraging suspicious COM objects"
        author = "Infra DFIR"
        scope = "lolbin/mshta"
    strings:
        $shell = "WScript.Shell" ascii wide nocase
        $getobject = "GetObject" ascii wide nocase
        $download = "XMLHTTP" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $shell and ($getobject or $download)
}
