rule PACKER_UPX
{
    meta:
        description = "Detect UPX-packed binaries"
        reference = "https://upx.github.io/"
    strings:
        $upx1 = "UPX!"
        $upx2 = "UPX0"
        $upx3 = "UPX1"
    condition:
        2 of ($upx*)
}

rule PACKER_ASPACK
{
    meta:
        description = "Detect ASPack-packed binaries"
    strings:
        $s1 = "ASPack"
        $s2 = { 41 53 50 61 63 6B }
    condition:
        any of them
}
