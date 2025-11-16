import "pe"

// Derived from signature-base focus on lateral movement toolmarks
rule SIGBASE_Lateral_PSExecSvc
{
    meta:
        description = "Detects PsExec service dropper patterns"
        reference = "signature-base/lateral_movement/psexec.yar"
        author = "Nextron Systems"
        scope = "vendor/signature-base"
    strings:
        $svc = "PSEXESVC" ascii nocase
        $service = "PsExec service" ascii nocase
        $pipe = "\\\\.\\pipe\\PSEXESVC" ascii
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $svc and ($service or $pipe)
}

rule SIGBASE_Lateral_WMICExec
{
    meta:
        description = "WMIC command execution helpers embedded in binaries"
        reference = "signature-base/lateral_movement/wmi_exec.yar"
        author = "Nextron Systems"
        scope = "vendor/signature-base"
    strings:
        $wmic = "wmic" ascii wide nocase
        $process = "process call create" ascii wide nocase
        $node = "/node:" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $wmic and $process and $node
}
