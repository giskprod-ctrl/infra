import "pe"

rule LOLBIN_Bitsadmin_Download
{
    meta:
        description = "BITSAdmin abused to download payloads"
        author = "Infra DFIR"
        scope = "lolbin/bitsadmin"
    strings:
        $bits = "bitsadmin" ascii wide nocase
        $transfer = "/transfer" ascii wide nocase
        $download = "/download" ascii wide nocase
        $addfile = "/addfile" ascii wide nocase
        $http = "http" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $bits and ($transfer or $download) and $addfile and $http
}

rule LOLBIN_Bitsadmin_ScheduledJob
{
    meta:
        description = "BITSAdmin creating a job for persistence"
        author = "Infra DFIR"
        scope = "lolbin/bitsadmin"
    strings:
        $bits = "bitsadmin" ascii wide nocase
        $create = "/create" ascii wide nocase
        $addfile = "/addfile" ascii wide nocase
        $setnotify = "/setnotifycmdline" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $bits and $create and $addfile and $setnotify
}
