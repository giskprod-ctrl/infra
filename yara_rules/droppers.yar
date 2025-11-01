rule GENERIC_Dropper
{
    meta:
        description = "Generic indicators of dropper behaviour"
    strings:
        $s1 = "regsvr32.exe"
        $s2 = "rundll32.exe"
        $s3 = "powershell.exe"
        $s4 = "cmd.exe /c"
        $s5 = "ShellExecute"
    condition:
        2 of ($s*)
}

rule GENERIC_WebDropper
{
    meta:
        description = "Downloads payloads via HTTP"
    strings:
        $h1 = "http://"
        $h2 = "https://"
        $h3 = "URLDownloadToFile"
        $h4 = "WinHttpOpen"
    condition:
        ($h3 or $h4) and ($h1 or $h2)
}
