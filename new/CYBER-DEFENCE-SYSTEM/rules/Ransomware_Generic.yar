rule Ransomware_Generic
{
    meta:
        author = "CYBERSHIELD"
        description = "Generic ransomware indicators (heuristic)"
        license = "MIT"

    strings:
        $s1 = "CreateRemoteThread"
        $s2 = "EncryptFile"
        $s3 = "FINDENCRYPTED" nocase
        $s4 = "WannaCrypt" nocase
        $s5 = "ransom" nocase

    condition:
        (1 of ($s*))
}
