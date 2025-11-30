/*
 * Archive-specific threats and suspicious patterns
 */

rule Archive_Bomb_Indicator
{
    meta:
        description = "Detects potential zip bombs with nested archives"
        severity = "high"
        category = "archive"
    strings:
        // Multiple compressed files in succession
        $zip1 = { 50 4B 03 04 }  // ZIP header
        $rar1 = { 52 61 72 21 }  // RAR header
        $gz1 = { 1F 8B }         // GZIP header
    condition:
        (#zip1 > 10 or #rar1 > 10 or #gz1 > 10)
}

rule Archive_Hidden_Executable
{
    meta:
        description = "Executable hidden in archive with misleading extension"
        severity = "high"
        category = "archive"
    strings:
        $mz = "MZ"
        $zip = { 50 4B 03 04 }
        $elf = { 7F 45 4C 46 }
        // Common misleading extensions in filename table
        $ext1 = ".pdf" nocase
        $ext2 = ".jpg" nocase
        $ext3 = ".doc" nocase
        $ext4 = ".txt" nocase
    condition:
        $zip and ($mz or $elf) and any of ($ext*)
}

rule Archive_Password_Protected_Suspicious
{
    meta:
        description = "Password-protected archive with suspicious characteristics"
        severity = "medium"
        category = "archive"
    strings:
        $zip_encrypted = { 50 4B 03 04 ?? ?? 01 00 }  // ZIP with encryption flag
        $rar_encrypted = { 52 61 72 21 1A 07 ?? ?? ?? ?? ?? 70 }
        // Suspicious filenames in encrypted archives
        $invoice = "invoice" nocase
        $payment = "payment" nocase
        $order = "order" nocase
        $urgent = "urgent" nocase
    condition:
        ($zip_encrypted or $rar_encrypted) and any of ($invoice, $payment, $order, $urgent)
}

rule Archive_Multiple_Executables
{
    meta:
        description = "Archive containing multiple executable files"
        severity = "medium"
        category = "archive"
    strings:
        $zip = { 50 4B 03 04 }
        $mz = "MZ" ascii
        $elf = { 7F 45 4C 46 }
        $exe = ".exe" nocase
    condition:
        $zip and (#mz > 3 or #elf > 3 or #exe > 3)
}

rule Archive_Macro_Document
{
    meta:
        description = "Archive containing Office document with macros"
        severity = "high"
        category = "archive"
    strings:
        $zip = { 50 4B 03 04 }
        // Office Open XML with VBA macros
        $vba1 = "vbaProject.bin"
        $vba2 = "word/vbaProject.bin"
        $vba3 = "xl/vbaProject.bin"
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }  // OLE2 header (old Office)
    condition:
        $zip and any of ($vba*) or $ole
}
