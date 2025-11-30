/*
   YARA Rule Collection - Suspicious Behaviors

   These rules detect suspicious but not necessarily malicious behaviors.
   Useful for threat hunting and behavioral analysis.

   Author: Valkyrie Security Team
   Version: 1.0
*/

rule Suspicious_File_Hidden {
    meta:
        description = "Detects hidden executable files"
        severity = "medium"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $hidden1 = "Hidden" ascii
        $hidden2 = ".exe" ascii

    condition:
        $hidden1 and $hidden2
}

rule Suspicious_Base64 {
    meta:
        description = "Detects base64 encoded suspicious content"
        severity = "low"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $b64_1 = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                   50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64
                   65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73
                   74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37
                   38 39 2B 2F 3D }  # Base64 alphabet

    condition:
        # At least 100 base64 characters
        $b64_1 at @b64_1 and @b64_1 + 100 < filesize
}

rule Suspicious_Registry_Access {
    meta:
        description = "Suspicious registry access patterns"
        severity = "medium"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $reg_run = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $reg_run_once = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii
        $reg_run_service = "HKLM\\System\\CurrentControlSet\\Services" ascii

    condition:
        any of them
}

rule Suspicious_Persistence {
    meta:
        description = "Suspicious persistence mechanisms"
        severity = "medium"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $task_sched = "schtasks" ascii
        $startup = "Startup" ascii
        $autorun = "Autorun" ascii
        $wmi = "WMI" ascii

    condition:
        any of them
}

rule Suspicious_Process_Injection {
    meta:
        description = "Suspicious process injection techniques"
        severity = "high"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $inject1 = "WriteProcessMemory" ascii
        $inject2 = "CreateRemoteThread" ascii
        $inject3 = "QueueUserAPC" ascii
        $inject4 = "SetWindowsHookEx" ascii

    condition:
        any of them
}

rule Suspicious_Mutex {
    meta:
        description = "Suspicious mutex creation patterns"
        severity = "low"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $mutex1 = "Global\\" ascii
        $mutex2 = "Mutex" ascii
        $mutex3 = "Lock" ascii

    condition:
        2 of them
}

rule Suspicious_Crypto {
    meta:
        description = "Suspicious cryptographic operations"
        severity = "medium"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $crypt1 = "CryptAcquireContext" ascii
        $crypt2 = "CryptEncrypt" ascii
        $crypt3 = "CryptDecrypt" ascii
        $xor1 = "xor" ascii
        $aes1 = "AES" ascii

    condition:
        any of ($crypt*) or ($aes1 and $xor1)
}

rule Suspicious_Sleep {
    meta:
        description = "Suspicious sleep/delay patterns (evasion)"
        severity = "low"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $sleep1 = "Sleep" ascii
        $wait1 = "WaitForSingleObject" ascii
        $delay1 = "delay" ascii
        $timeout1 = "timeout" ascii

    condition:
        any of them
}

rule Suspicious_Obfuscation {
    meta:
        description = "Suspicious code obfuscation"
        severity = "medium"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $obf1 = { 90 90 90 }  // NOP sleds
        $obf2 = "rot13" ascii
        $obf3 = "caesar" ascii

    condition:
        any of them
}

rule Suspicious_AntiAnalysis {
    meta:
        description = "Anti-analysis and evasion techniques"
        severity = "high"
        author = "Valkyrie"
        date = "2025-01-01"

    strings:
        $anti_vm = "vmware" ascii
        $anti-debug = "IsDebuggerPresent" ascii
        $anti-sandbox = "sandbox" ascii
        $check-debug = "CheckRemoteDebuggerPresent" ascii

    condition:
        any of them
}
