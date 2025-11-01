rule WIN32_CreateRemoteThread
{
    meta:
        description = "Detect APIs commonly used for remote thread injection"
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "VirtualAllocEx"
        $api3 = "WriteProcessMemory"
        $api4 = "OpenProcess"
    condition:
        3 of ($api*)
}

rule WIN32_ProcessHollowing
{
    meta:
        description = "Indicators of process hollowing techniques"
    strings:
        $s1 = "ZwUnmapViewOfSection"
        $s2 = "NtUnmapViewOfSection"
        $s3 = "SetThreadContext"
        $s4 = "ResumeThread"
    condition:
        all of ($s*)
}
