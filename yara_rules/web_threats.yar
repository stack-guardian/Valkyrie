/*
 * Web-based threats: PHP shells, malicious JavaScript, web shells
 */

rule WebShell_PHP_Generic
{
    meta:
        description = "Generic PHP web shell indicators"
        severity = "critical"
        category = "webshell"
    strings:
        $php = "<?php"
        $eval1 = "eval(" nocase
        $exec1 = "exec(" nocase
        $system1 = "system(" nocase
        $shell1 = "shell_exec(" nocase
        $base64 = "base64_decode(" nocase
        $assert = "assert(" nocase
        $passthru = "passthru(" nocase
    condition:
        $php and 2 of ($eval1, $exec1, $system1, $shell1, $base64, $assert, $passthru)
}

rule WebShell_Upload_Function
{
    meta:
        description = "PHP file upload functionality in web shell"
        severity = "high"
        category = "webshell"
    strings:
        $php = "<?php"
        $upload1 = "$_FILES" nocase
        $upload2 = "move_uploaded_file" nocase
        $upload3 = "file_put_contents" nocase
        $exec = /exec|system|shell_exec|passthru/ nocase
    condition:
        $php and any of ($upload*) and $exec
}

rule JavaScript_Obfuscated_Malicious
{
    meta:
        description = "Heavily obfuscated JavaScript with suspicious patterns"
        severity = "high"
        category = "javascript"
    strings:
        $js1 = "<script"
        $js2 = "javascript:"
        // Obfuscation patterns
        $hex1 = /\\x[0-9a-f]{2}/i
        $unicode1 = /\\u[0-9a-f]{4}/i
        $eval = "eval(" nocase
        $fromchar = "fromCharCode" nocase
        $unescape = "unescape(" nocase
        // Long chains of encoded characters
        $chain = /(\+\"\\x[0-9a-f]{2}){20,}/i
    condition:
        ($js1 or $js2) and $eval and ($fromchar or $unescape) and (#hex1 > 50 or #unicode1 > 50 or $chain)
}

rule WebShell_C99_Variants
{
    meta:
        description = "C99, r57, WSO web shell variants"
        severity = "critical"
        category = "webshell"
    strings:
        $c99_1 = "c99shell" nocase
        $c99_2 = "c99sh" nocase
        $r57 = "r57shell" nocase
        $wso = "WSO " nocase
        $b374k = "b374k" nocase
        $pass = "$password" nocase
        $md5 = "md5($_POST" nocase
    condition:
        any of ($c99*, $r57, $wso, $b374k) or ($pass and $md5)
}

rule SQL_Injection_Tool
{
    meta:
        description = "SQL injection tool or dumper"
        severity = "high"
        category = "exploit"
    strings:
        $sql1 = "union select" nocase
        $sql2 = "concat(" nocase
        $sql3 = "information_schema" nocase
        $dump1 = "database()" nocase
        $dump2 = "table_name" nocase
        $dump3 = "column_name" nocase
        $sqli = "sqlmap" nocase
    condition:
        $sqli or (3 of ($sql*, $dump*))
}

rule Phishing_Credential_Harvester
{
    meta:
        description = "Phishing page credential harvester"
        severity = "critical"
        category = "phishing"
    strings:
        $form = "<form" nocase
        $post1 = "method=\"post\"" nocase
        $post2 = "method='post'" nocase
        $pass1 = "type=\"password\"" nocase
        $pass2 = "name=\"password\"" nocase
        $pass3 = "name=\"pass\"" nocase
        $email = /name=(\")?email/i
        $user = /name=(\")?user/i
        // Data exfiltration
        $mailto = "mailto:" nocase
        $curl = "curl " nocase
        $file_put = "file_put_contents" nocase
        $mail = "mail(" nocase
    condition:
        $form and any of ($post*) and any of ($pass*) and any of ($email, $user) and any of ($mailto, $curl, $file_put, $mail)
}
