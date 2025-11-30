"""
Scanning mode configurations for Valkyrie
Defines different scanning profiles: High, Medium, Low, Disabled
"""

SCANNING_MODES = {
    "high": {
        "name": "High Security",
        "description": "Maximum protection with all engines and heuristics enabled",
        "clamav": True,
        "yara": True,
        "heuristics": True,
        "archive_inspection": True,
        "entropy_analysis": True,
        "packer_detection": True,
        "recursive_archives": True,
        "max_archive_depth": 3,
        "string_analysis": True,
        "thresholds": {
            "quarantine": 70,  # More aggressive
            "review": 30
        },
        "scoring": {
            "clamav_signature": 100,
            "yara_critical": 90,
            "yara_high": 70,
            "yara_medium": 40,
            "yara_low": 20,
            "entropy_high": 30,
            "entropy_suspicious": 15,
            "packer_detected": 30,
            "file_type_mismatch": 25,
            "archive_bomb": 60,
            "archive_encrypted": 20,
            "archive_executables": 25,
            "double_extension": 35,
            "suspicious_strings": 20
        }
    },
    
    "medium": {
        "name": "Balanced",
        "description": "Good protection with reasonable performance",
        "clamav": True,
        "yara": True,
        "heuristics": False,
        "archive_inspection": True,
        "entropy_analysis": False,
        "packer_detection": True,
        "recursive_archives": False,
        "max_archive_depth": 2,
        "string_analysis": False,
        "thresholds": {
            "quarantine": 80,  # Standard
            "review": 40
        },
        "scoring": {
            "clamav_signature": 100,
            "yara_critical": 90,
            "yara_high": 70,
            "yara_medium": 40,
            "yara_low": 20,
            "entropy_high": 0,
            "entropy_suspicious": 0,
            "packer_detected": 25,
            "file_type_mismatch": 20,
            "archive_bomb": 50,
            "archive_encrypted": 10,
            "archive_executables": 15,
            "double_extension": 30,
            "suspicious_strings": 0
        }
    },
    
    "low": {
        "name": "Low Security",
        "description": "Basic protection, signature-based only",
        "clamav": True,
        "yara": False,
        "heuristics": False,
        "archive_inspection": False,
        "entropy_analysis": False,
        "packer_detection": False,
        "recursive_archives": False,
        "max_archive_depth": 0,
        "string_analysis": False,
        "thresholds": {
            "quarantine": 90,  # Very conservative
            "review": 50
        },
        "scoring": {
            "clamav_signature": 100,
            "yara_critical": 0,
            "yara_high": 0,
            "yara_medium": 0,
            "yara_low": 0,
            "entropy_high": 0,
            "entropy_suspicious": 0,
            "packer_detected": 0,
            "file_type_mismatch": 0,
            "archive_bomb": 0,
            "archive_encrypted": 0,
            "archive_executables": 0,
            "double_extension": 0,
            "suspicious_strings": 0
        }
    },
    
    "disabled": {
        "name": "Disabled",
        "description": "All scanning disabled (monitoring only)",
        "clamav": False,
        "yara": False,
        "heuristics": False,
        "archive_inspection": False,
        "entropy_analysis": False,
        "packer_detection": False,
        "recursive_archives": False,
        "max_archive_depth": 0,
        "string_analysis": False,
        "thresholds": {
            "quarantine": 999,  # Never quarantine
            "review": 999
        },
        "scoring": {
            "clamav_signature": 0,
            "yara_critical": 0,
            "yara_high": 0,
            "yara_medium": 0,
            "yara_low": 0,
            "entropy_high": 0,
            "entropy_suspicious": 0,
            "packer_detected": 0,
            "file_type_mismatch": 0,
            "archive_bomb": 0,
            "archive_encrypted": 0,
            "archive_executables": 0,
            "double_extension": 0,
            "suspicious_strings": 0
        }
    }
}

def get_mode_config(mode: str) -> dict:
    """
    Get configuration for a specific scanning mode
    Returns medium mode if invalid mode specified
    """
    return SCANNING_MODES.get(mode.lower(), SCANNING_MODES["medium"])

def list_modes() -> list:
    """
    Get list of available scanning modes
    """
    return [
        {
            "id": mode_id,
            "name": config["name"],
            "description": config["description"]
        }
        for mode_id, config in SCANNING_MODES.items()
    ]
