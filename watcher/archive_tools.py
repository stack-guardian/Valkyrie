"""
Archive analysis tools integration
Provides deep inspection of ZIP, RAR, 7Z and other archive formats
"""
import subprocess
import os
import json
from typing import Dict, List, Any

def get_archive_info(path: str) -> Dict[str, Any]:
    """
    Extract detailed information about archive contents
    """
    result = {
        "is_archive": False,
        "type": None,
        "file_count": 0,
        "files": [],
        "encrypted": False,
        "compression_ratio": 0.0,
        "suspicious": False,
        "warnings": []
    }
    
    # Detect archive type using file command
    try:
        mime_result = subprocess.run(
            ["file", "-b", "--mime-type", path],
            capture_output=True, text=True, timeout=5
        )
        mime_type = mime_result.stdout.strip()
        
        if "zip" in mime_type or "compressed" in mime_type:
            result["is_archive"] = True
            result["type"] = mime_type
    except Exception:
        pass
    
    if not result["is_archive"]:
        return result
    
    # Try 7z for detailed analysis (supports most formats)
    try:
        list_result = subprocess.run(
            ["7z", "l", "-slt", path],
            capture_output=True, text=True, timeout=15
        )
        
        if list_result.returncode == 0:
            output = list_result.stdout
            result = parse_7z_output(output, result)
        else:
            # Try zipinfo for ZIP files
            result = try_zipinfo(path, result)
    except Exception as e:
        result["warnings"].append(f"Archive analysis error: {str(e)}")
    
    # Check for suspicious patterns
    result["suspicious"] = check_suspicious_archive(result)
    
    return result

def parse_7z_output(output: str, result: Dict) -> Dict:
    """Parse 7z list output"""
    files = []
    encrypted = False
    total_size = 0
    compressed_size = 0
    
    current_file = {}
    for line in output.split('\n'):
        line = line.strip()
        
        if line.startswith("Path = "):
            if current_file and current_file.get("name"):
                files.append(current_file)
            current_file = {"name": line[7:]}
        elif line.startswith("Size = "):
            try:
                size = int(line[7:])
                current_file["size"] = size
                total_size += size
            except ValueError:
                pass
        elif line.startswith("Packed Size = "):
            try:
                packed = int(line[14:])
                current_file["packed_size"] = packed
                compressed_size += packed
            except ValueError:
                pass
        elif line.startswith("Encrypted = +"):
            encrypted = True
            current_file["encrypted"] = True
        elif line.startswith("Attributes = "):
            current_file["attributes"] = line[13:]
    
    if current_file and current_file.get("name"):
        files.append(current_file)
    
    result["files"] = files
    result["file_count"] = len(files)
    result["encrypted"] = encrypted
    
    if total_size > 0 and compressed_size > 0:
        result["compression_ratio"] = total_size / compressed_size
    
    return result

def try_zipinfo(path: str, result: Dict) -> Dict:
    """Fallback to zipinfo for ZIP files"""
    try:
        zip_result = subprocess.run(
            ["zipinfo", "-1", path],
            capture_output=True, text=True, timeout=10
        )
        
        if zip_result.returncode == 0:
            files = [{"name": f.strip()} for f in zip_result.stdout.split('\n') if f.strip()]
            result["files"] = files
            result["file_count"] = len(files)
    except Exception:
        pass
    
    return result

def check_suspicious_archive(info: Dict) -> bool:
    """
    Check for suspicious archive characteristics
    """
    warnings = []
    suspicious = False
    
    # Check compression ratio (potential zip bomb)
    if info.get("compression_ratio", 0) > 100:
        warnings.append("Extremely high compression ratio (potential zip bomb)")
        suspicious = True
    
    # Check for encrypted archives
    if info.get("encrypted"):
        warnings.append("Archive is password protected")
    
    # Check for executables in archive
    exe_count = 0
    for file_info in info.get("files", []):
        name = file_info.get("name", "").lower()
        if name.endswith((".exe", ".dll", ".so", ".sh", ".bat", ".cmd", ".vbs", ".ps1")):
            exe_count += 1
    
    if exe_count > 0:
        warnings.append(f"Contains {exe_count} executable file(s)")
        if exe_count > 3:
            suspicious = True
    
    # Check for double extensions
    for file_info in info.get("files", []):
        name = file_info.get("name", "").lower()
        # Check for patterns like "invoice.pdf.exe"
        if ".pdf." in name or ".doc." in name or ".jpg." in name or ".txt." in name:
            warnings.append(f"Suspicious double extension: {name}")
            suspicious = True
    
    # Check for nested archives (potential bomb)
    nested_count = sum(1 for f in info.get("files", []) 
                      if f.get("name", "").lower().endswith((".zip", ".rar", ".7z", ".gz", ".tar")))
    if nested_count > 5:
        warnings.append(f"Contains {nested_count} nested archives")
        suspicious = True
    
    # Check file count (potential bomb)
    if info.get("file_count", 0) > 1000:
        warnings.append(f"Very large file count: {info['file_count']}")
        suspicious = True
    
    info["warnings"].extend(warnings)
    return suspicious

def extract_and_scan_archive(path: str, temp_dir: str) -> List[str]:
    """
    Safely extract archive to temp directory and return list of extracted files
    Returns empty list on error
    """
    extracted_files = []
    
    try:
        # Use 7z to extract with limits
        extract_result = subprocess.run(
            ["7z", "x", f"-o{temp_dir}", "-y", path],
            capture_output=True, text=True, timeout=30
        )
        
        if extract_result.returncode == 0:
            # List extracted files
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    extracted_files.append(os.path.join(root, file))
    except Exception:
        pass
    
    return extracted_files

def get_strings_from_file(path: str, min_length: int = 6, max_strings: int = 1000) -> List[str]:
    """
    Extract printable strings from file (useful for analyzing archives)
    """
    strings_list = []
    
    try:
        result = subprocess.run(
            ["strings", "-n", str(min_length), path],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode == 0:
            strings_list = result.stdout.split('\n')[:max_strings]
    except Exception:
        pass
    
    return [s.strip() for s in strings_list if s.strip()]
