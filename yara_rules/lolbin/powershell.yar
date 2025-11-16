import "pe"

rule LOLBIN_PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell used with encoded command switch"
        author = "Infra DFIR"
        scope = "lolbin/powershell"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc = "-encodedcommand" ascii wide nocase
        $nop = "-nop" ascii wide nocase
        $wflag = "-windowstyle hidden" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $ps and $enc and ($nop or $wflag)
}

rule LOLBIN_PowerShell_RemoteDownload
{
    meta:
        description = "PowerShell downloading remote payloads"
        author = "Infra DFIR"
        scope = "lolbin/powershell"
    strings:
        $ps = "powershell" ascii wide nocase
        $webclient = "System.Net.WebClient" ascii wide nocase
        $download = "DownloadString" ascii wide nocase
        $iex = "IEX" ascii nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $ps and $webclient and ($download or $iex)
}
