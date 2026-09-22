rule EICAR_Test_File
{
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_DownloadCradle
{
    strings:
        $a = "IEX (New-Object Net.WebClient).DownloadString(" nocase
        $b = "FromBase64String(" nocase
        $c = "powershell -enc" nocase
    condition:
        filesize < 2MB and 2 of ($a,$b,$c)
}

rule Suspicious_Lolbin_Chains
{
    strings:
        $a = "mshta http" nocase
        $b = "regsvr32 /s /u /i:http" nocase
        $c = "rundll32" nocase
    condition:
        filesize < 2MB and 2 of ($a,$b,$c)
}

rule Android_RAT_Builder_Telegram
{
    strings:
        $a = "api.telegram.org/bot" nocase
        $b = "RECEIVE_BOOT_COMPLETED" nocase
        $c = "startForegroundService" nocase
        $d = "Runtime.getRuntime().exec" nocase
        $e = "android.permission.READ_SMS" nocase
    condition:
        filesize < 4MB and $a and $d and 2 of ($b,$c,$e)
}
