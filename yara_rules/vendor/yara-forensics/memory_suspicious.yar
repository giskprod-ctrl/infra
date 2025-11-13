import "pe"

// Derived from https://github.com/ThreatHuntingProject/yara-forensics
rule YF_Memory_SuspiciousSection
{
    meta:
        description = "Executable section created in writable memory"
        author = "Threat Hunting Project"
        scope = "vendor/yara-forensics"
    condition:
        uint16(0) == 0x5a4d and pe.is_pe and for any i in (0..pe.number_of_sections - 1) :
            (pe.sections[i].characteristics & pe.SECTION_EXECUTABLE and
             pe.sections[i].characteristics & pe.SECTION_WRITABLE and
             pe.sections[i].raw_data_size == 0)
}
