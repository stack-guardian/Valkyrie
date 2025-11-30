/*
 * Malicious scripts: PowerShell, Bash, Python, etc.
 */

rule PowerShell_Download_Execute
{
    meta:
        description = "PowerShell script downloading and executing payload"
        severity = "critical"
        category = "script"
    strings:
        // Download methods
        $download1 = "DownloadFile" nocase
        $download2 = "DownloadString" nocase
        $download3 = "wget" nocase
        $download4 = "Invoke-WebRequest" nocase
        $download5 = "IWR" nocase
        $download6 = "curl" nocase
        // Execution methods
        $exec1 = "Invoke-Expression" nocase
        $exec2 = "IEX" nocase
        $exec3 = "Start-Process" nocase
        $exec4 = "&" ascii
        $exec5 = "Invoke-Command" nocase
    condition:
        any of ($download*) and any of ($exec*)
}

rule PowerShell_Base64_Obfuscation
{
    meta:
        description = "PowerShell with base64 encoded commands"
        severity = "high"
        category = "script"
    strings:
        $ps = "powershell" nocase
        $encoded1 = "-enc" nocase
        $encoded2 = "-e " nocase
        $encoded3 = "-EncodedCommand" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
    condition:
        $ps and any of ($encoded*) and ($hidden or $bypass)
}

rule PowerShell_Empire_Stager
{
    meta:
        description = "PowerShell Empire or similar framework stager"
        severity = "critical"
        category = "c2"
    strings:
        $empire1 = "GetCommandLineW" nocase
        $empire2 = "system.net.webclient" nocase
        $empire3 = "FromBase64String" nocase
        $stage = "GetBytes" nocase
        $gzip = "IO.Compression.GzipStream" nocase
    condition:
        3 of them
}

rule Bash_Reverse_Shell
{
    meta:
        description = "Bash reverse shell connection"
        severity = "critical"
        category = "backdoor"
    strings:
        $shebang = "#!/bin/bash"
        $bash = "/bin/bash"
        $nc1 = "nc " nocase
        $nc2 = "netcat" nocase
        $dev_tcp = "/dev/tcp/"
        $redirect1 = ">&"
        $redirect2 = "2>&1"
        $pipe = "|"
    condition:
        ($shebang or $bash) and ($nc1 or $nc2 or $dev_tcp) and any of ($redirect*, $pipe)
}

rule Python_Obfuscated_Import
{
    meta:
        description = "Python script with obfuscated imports (potential malware)"
        severity = "high"
        category = "script"
    strings:
        $python = "#!/usr/bin/python" nocase
        $import1 = "__import__" nocase
        $compile = "compile(" nocase
        $exec = "exec(" nocase
        $eval = "eval(" nocase
        $base64 = "base64" nocase
        $socket = "socket" nocase
        $subprocess = "subprocess" nocase
    condition:
        ($python or $import1) and $compile and ($exec or $eval) and $base64
}

rule Python_Keylogger
{
    meta:
        description = "Python keylogger script"
        severity = "critical"
        category = "spyware"
    strings:
        $python = "python" nocase
        $pynput = "pynput" nocase
        $keyboard1 = "Keyboard" nocase
        $keyboard2 = "on_press" nocase
        $listener = "Listener" nocase
        $log = ".log" nocase
        $key = "key" nocase
    condition:
        ($python or $pynput) and $keyboard1 and $keyboard2 and $listener
}

rule Batch_Malicious_Commands
{
    meta:
        description = "Batch file with malicious commands"
        severity = "high"
        category = "script"
    strings:
        $bat = "@echo off" nocase
        // Persistence
        $reg1 = "reg add" nocase
        $reg2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $schtasks = "schtasks" nocase
        // Network activity
        $download1 = "powershell" nocase
        $download2 = "certutil" nocase
        $download3 = "bitsadmin" nocase
        // Execution
        $start = "start /b" nocase
        $mshta = "mshta" nocase
    condition:
        $bat and 3 of them
}

rule VBS_Downloader
{
    meta:
        description = "VBScript downloading and executing files"
        severity = "critical"
        category = "script"
    strings:
        $vbs1 = "CreateObject" nocase
        $vbs2 = "WScript.Shell" nocase
        $download1 = "MSXML2.XMLHTTP" nocase
        $download2 = "MSXML2.ServerXMLHTTP" nocase
        $download3 = "URLDownloadToFile" nocase
        $save1 = "SaveToFile" nocase
        $save2 = "Open" nocase
        $exec1 = ".Run" nocase
        $exec2 = "Execute" nocase
    condition:
        2 of ($vbs*) and any of ($download*) and any of ($save*) and any of ($exec*)
}
