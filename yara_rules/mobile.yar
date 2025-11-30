/*
 * Mobile malware: Android APK, iOS threats
 */

rule Android_APK_Suspicious_Permissions
{
    meta:
        description = "Android APK requesting dangerous permission combinations"
        severity = "high"
        category = "mobile"
    strings:
        $apk = { 50 4B 03 04 }
        $manifest = "AndroidManifest.xml"
        // Dangerous permissions
        $sms1 = "SEND_SMS" nocase
        $sms2 = "READ_SMS" nocase
        $sms3 = "RECEIVE_SMS" nocase
        $call1 = "CALL_PHONE" nocase
        $call2 = "READ_CALL_LOG" nocase
        $location = "ACCESS_FINE_LOCATION" nocase
        $contacts = "READ_CONTACTS" nocase
        $camera = "CAMERA" nocase
        $record = "RECORD_AUDIO" nocase
        $admin = "BIND_DEVICE_ADMIN" nocase
    condition:
        $apk and $manifest and 4 of ($sms*, $call*, $location, $contacts, $camera, $record, $admin)
}

rule Android_Native_Library_Packer
{
    meta:
        description = "Android APK with native library obfuscation/packing"
        severity = "medium"
        category = "mobile"
    strings:
        $apk = { 50 4B 03 04 }
        $dex = "classes.dex"
        $lib = "lib/"
        $so = ".so"
        // Packer indicators
        $upx = "UPX" nocase
        $packed = "packed" nocase
        $stub = "stub" nocase
    condition:
        $apk and $dex and $lib and $so and any of ($upx, $packed, $stub)
}

rule Android_SMS_Trojan
{
    meta:
        description = "Android SMS trojan sending premium SMS"
        severity = "critical"
        category = "mobile"
    strings:
        $apk = { 50 4B 03 04 }
        $sms_manager = "SmsManager" nocase
        $send_text = "sendTextMessage" nocase
        // Premium rate numbers
        $premium1 = /\+?[0-9]{4,5}/ // Short codes
        $premium2 = "premium" nocase
        $subscribe = "subscribe" nocase
    condition:
        $apk and $sms_manager and $send_text and any of ($premium*, $subscribe)
}

rule Android_Banking_Trojan
{
    meta:
        description = "Android banking trojan with overlay attack"
        severity = "critical"
        category = "mobile"
    strings:
        $apk = { 50 4B 03 04 }
        $overlay = "TYPE_SYSTEM_OVERLAY" nocase
        $accessibility = "AccessibilityService" nocase
        $admin = "DeviceAdminReceiver" nocase
        // Banking keywords
        $bank1 = "bank" nocase
        $bank2 = "account" nocase
        $card = "card" nocase
        $pin = "pin" nocase
    condition:
        $apk and ($overlay or $accessibility) and $admin and 2 of ($bank*, $card, $pin)
}

rule iOS_Suspicious_Entitlements
{
    meta:
        description = "iOS app with suspicious entitlements"
        severity = "medium"
        category = "mobile"
    strings:
        $ipa = { 50 4B 03 04 }
        $plist = ".plist"
        $entitle = "entitlements" nocase
        // Suspicious capabilities
        $keychain = "keychain-access-groups" nocase
        $background = "UIBackgroundModes" nocase
        $location = "location" nocase
        $camera = "NSCameraUsageDescription" nocase
        $mic = "NSMicrophoneUsageDescription" nocase
    condition:
        $ipa and $plist and 3 of ($entitle, $keychain, $background, $location, $camera, $mic)
}
