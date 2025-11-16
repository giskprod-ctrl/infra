import "pe"

// Derived from Elastic Security coverage on defense evasion
rule ELASTIC_Suspicious_ImageLoad
{
    meta:
        description = "Detects LOLBIN image load anomalies"
        author = "Elastic Security"
        scope = "vendor/elastic"
    strings:
        $regsvr = "regsvr32" ascii wide nocase
        $scrobj = "scrobj.dll" ascii wide nocase
        $url = "http" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $regsvr and $scrobj and $url
}

rule ELASTIC_Suspicious_ScriptControl
{
    meta:
        description = "Scripting engine abuse for defense evasion"
        author = "Elastic Security"
        scope = "vendor/elastic"
    strings:
        $scriptcontrol = "MSScriptControl.ScriptControl" ascii wide nocase
        $language = "Language" ascii wide nocase
        $addcode = "AddCode" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $scriptcontrol and $language and $addcode
}
