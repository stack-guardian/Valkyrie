/*
 * Malicious document threats: macro viruses, embedded exploits, PDF malware
 */

rule Office_Macro_AutoRun
{
    meta:
        description = "Office document with auto-executing macro"
        severity = "high"
        category = "macro"
    strings:
        // Office file signatures
        $office_zip = { 50 4B 03 04 }
        $office_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        // VBA autorun functions
        $auto1 = "AutoOpen" nocase
        $auto2 = "AutoExec" nocase
        $auto3 = "Auto_Open" nocase
        $auto4 = "Workbook_Open" nocase
        $auto5 = "Document_Open" nocase
        $auto6 = "AutoClose" nocase
    condition:
        ($office_zip or $office_ole) and any of ($auto*)
}

rule Office_Macro_Suspicious_Commands
{
    meta:
        description = "Office macro with suspicious system commands"
        severity = "critical"
        category = "macro"
    strings:
        $office = { D0 CF 11 E0 }
        // VBA suspicious functions
        $shell = "Shell(" nocase
        $wscript = "WScript.Shell" nocase
        $create = "CreateObject" nocase
        $powershell = "powershell" nocase
        $cmd = "cmd.exe" nocase
        $download = "URLDownloadToFile" nocase
        $exec = "ExecuteStatement" nocase
        $run = ".Run" nocase
    condition:
        $office and 2 of ($shell, $wscript, $create, $powershell, $cmd, $download, $exec, $run)
}

rule PDF_Embedded_JavaScript
{
    meta:
        description = "PDF with embedded JavaScript (potential exploit)"
        severity = "high"
        category = "pdf"
    strings:
        $pdf = "%PDF-"
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $aa = "/AA" nocase  // Auto-action
        $openaction = "/OpenAction" nocase
        $launch = "/Launch" nocase
    condition:
        $pdf at 0 and ($js1 or $js2) and ($aa or $openaction or $launch)
}

rule PDF_Embedded_File
{
    meta:
        description = "PDF with embedded executable or suspicious file"
        severity = "medium"
        category = "pdf"
    strings:
        $pdf = "%PDF-"
        $embed = "/EmbeddedFile" nocase
        $filespec = "/FileSpec" nocase
        $mz = "MZ"
        $exe = ".exe" nocase
        $bat = ".bat" nocase
        $js = ".js" nocase
    condition:
        $pdf at 0 and ($embed or $filespec) and ($mz or $exe or $bat or $js)
}

rule RTF_Exploit_CVE
{
    meta:
        description = "RTF file with exploit characteristics"
        severity = "critical"
        category = "exploit"
    strings:
        $rtf = "{\\rt"
        $objdata = "objdata" nocase
        $objclass = "objclass" nocase
        // Common exploit patterns
        $shellcode = { 90 90 90 90 }  // NOP sled
        $embedded_ole = { D0 CF 11 E0 }
        $equation = "Equation.3" nocase
    condition:
        $rtf at 0 and $objdata and ($shellcode or $embedded_ole or $equation)
}

rule Office_DDE_Injection
{
    meta:
        description = "Office document with DDE (Dynamic Data Exchange) injection"
        severity = "high"
        category = "exploit"
    strings:
        $office = { 50 4B 03 04 }
        $dde1 = "DDEAUTO" nocase
        $dde2 = "DDE" nocase
        $cmd = "cmd" nocase
        $powershell = "powershell" nocase
    condition:
        $office and ($dde1 or ($dde2 and ($cmd or $powershell)))
}

rule Document_Suspicious_URL
{
    meta:
        description = "Document containing suspicious shortened or obfuscated URLs"
        severity = "medium"
        category = "phishing"
    strings:
        // URL shorteners
        $url1 = "bit.ly" nocase
        $url2 = "tinyurl" nocase
        $url3 = "goo.gl" nocase
        $url4 = "ow.ly" nocase
        // Suspicious TLDs
        $tld1 = ".tk" nocase
        $tld2 = ".ml" nocase
        $tld3 = ".ga" nocase
        $tld4 = ".xyz" nocase
        // Base64 encoded URLs
        $b64url = /aHR0c[A-Za-z0-9+\/=]{20,}/
    condition:
        2 of them
}
