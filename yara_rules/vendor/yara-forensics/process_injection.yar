import "pe"

// Derived from yara-forensics process injection coverage
rule YF_ProcessInjection_APIs
{
    meta:
        description = "Common process injection API sequence"
        author = "Threat Hunting Project"
        scope = "vendor/yara-forensics"
    strings:
        $open = "OpenProcess" ascii wide nocase
        $alloc = "VirtualAllocEx" ascii wide nocase
        $write = "WriteProcessMemory" ascii wide nocase
        $exec = "CreateRemoteThread" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and 3 of ($open, $alloc, $write, $exec)
}

rule YF_ProcessInjection_Syscalls
{
    meta:
        description = "Native syscall process injection pattern"
        author = "Threat Hunting Project"
        scope = "vendor/yara-forensics"
    strings:
        $zwallocate = "ZwAllocateVirtualMemory" ascii wide nocase
        $zwwrite = "ZwWriteVirtualMemory" ascii wide nocase
        $zwqueue = "ZwQueueApcThread" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and $zwallocate and $zwwrite and $zwqueue
}
