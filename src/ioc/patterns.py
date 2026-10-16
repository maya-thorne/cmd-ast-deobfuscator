"""
Malware IOC regex patterns, LOLBins registry, and MITRE ATT&CK technique mappings.
"""

from enum import Enum
import re
from typing import Dict, List, Optional, Set, Tuple

from .models import MitreAttackMapping, MitreTactic


# =========================================================================
# 1. Network & Identity Patterns
# =========================================================================

# Strict IPv4 octet validation pattern (0-255)
IPV4_REGEX = re.compile(
    r"(?<![0-9a-zA-Z\.\-_])"
    r"((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))"
    r"(?::(\d{1,5}))?"
    r"(?![0-9a-zA-Z\.\-_])"
)

# IPv6 Address regex pattern with IPv4-mapped support and strict boundary
IPV6_REGEX = re.compile(
    r"(?<![0-9a-zA-Z:])"
    r"((?:::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|"
    r":(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|"
    r"fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,})"
    r"(?![0-9a-zA-Z:\.])"
)

# Standard URL pattern for cmd scripts (http, https, ftp, sftp, ws, wss, smb, file)
URL_REGEX = re.compile(
    r"(?i)\b((?:https?|ftp|sftp|ws|wss|file|smb)://[a-zA-Z0-9_\-\.\~%!$&\'()*+,;=:@/?#\[\]]+)"
)

# Common top-level domains for standalone FQDN matching
COMMON_TLDS = (
    "com|net|org|edu|gov|mil|int|io|co|cc|xyz|top|biz|info|me|ru|cn|de|uk|ai|"
    "live|online|site|club|work|vip|tk|ml|ga|cf|gq|tech|pro|store|app|dev|"
    "cloud|link|click|space|pw|buzz|to|is|su|onion|kr|jp|eu|ch|nl|fr|ca|in|br"
)

# Standalone domain pattern excluding script / executable extensions
DOMAIN_REGEX = re.compile(
    rf"(?i)\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+(?:{COMMON_TLDS}))\b"
)

# Email address regex
EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# Known native Windows DOS / console binaries ending in .com (to exclude from domain IOCs)
KNOWN_WINDOWS_COM_FILES: Set[str] = {
    "tree.com", "more.com", "chcp.com", "format.com", "diskcomp.com",
    "diskcopy.com", "mode.com", "command.com", "edit.com", "debug.com",
    "win.com", "graftabl.com", "loadfix.com"
}

# Runner binaries commonly abused to execute dropped scripts, libraries, or payloads
RUNNER_BINS: Set[str] = {
    "wscript", "wscript.exe", "cscript", "cscript.exe", "mshta", "mshta.exe",
    "rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe", "start"
}

# Standard Windows system dynamic libraries to exclude from file drop extraction
KNOWN_SYSTEM_DLLS: Set[str] = {
    "shell32.dll", "scrobj.dll", "user32.dll", "kernel32.dll", "ntdll.dll",
    "advapi32.dll", "ole32.dll", "oleaut32.dll", "shlwapi.dll", "setupapi.dll",
    "urlmon.dll", "msvcrt.dll"
}



# =========================================================================
# 2. File & Cryptographic Hash Patterns
# =========================================================================

# File extensions frequently associated with dropper payloads & malware artifacts
EXECUTABLE_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".ps1", ".psm1", ".psd1", ".hta", ".cpl", ".wsf",
    ".reg", ".msi", ".inf", ".ocx", ".jar", ".bin", ".iso", ".vhd"
}

# Regex to detect dropped filenames or executable artifacts in command arguments
FILE_DROP_REGEX = re.compile(
    r"(?i)\b([a-zA-Z0-9_\-\.\%\$]+\.(?:exe|dll|sys|scr|bat|cmd|vbs|vbe|js|jse|ps1|psm1|hta|cpl|wsf|reg|msi|inf|ocx))\b"
)

# Cryptographic hash patterns
MD5_REGEX = re.compile(r"(?i)\b([a-f0-9]{32})\b")
SHA1_REGEX = re.compile(r"(?i)\b([a-f0-9]{40})\b")
SHA256_REGEX = re.compile(r"(?i)\b([a-f0-9]{64})\b")


# =========================================================================
# 3. MITRE ATT&CK Catalog
# =========================================================================

MITRE_CATALOG: Dict[str, Tuple[str, MitreTactic]] = {
    "T1059.003": ("Windows Command Shell", MitreTactic.EXECUTION),
    "T1059.001": ("PowerShell", MitreTactic.EXECUTION),
    "T1059.005": ("Visual Basic / VBScript", MitreTactic.EXECUTION),
    "T1059.007": ("JavaScript", MitreTactic.EXECUTION),
    "T1105": ("Ingress Tool Transfer", MitreTactic.COMMAND_AND_CONTROL),
    "T1140": ("Deobfuscate/Decode Files or Information", MitreTactic.DEFENSE_EVASION),
    "T1197": ("BITS Jobs", MitreTactic.DEFENSE_EVASION),
    "T1218": ("System Binary Proxy Execution", MitreTactic.DEFENSE_EVASION),
    "T1218.005": ("Mshta", MitreTactic.DEFENSE_EVASION),
    "T1218.010": ("Regsvr32", MitreTactic.DEFENSE_EVASION),
    "T1218.011": ("Rundll32", MitreTactic.DEFENSE_EVASION),
    "T1218.001": ("Compiled HTML Help (hh.exe)", MitreTactic.DEFENSE_EVASION),
    "T1218.003": ("CMSTP", MitreTactic.DEFENSE_EVASION),
    "T1218.004": ("InstallUtil", MitreTactic.DEFENSE_EVASION),
    "T1047": ("Windows Management Instrumentation", MitreTactic.EXECUTION),
    "T1053.005": ("Scheduled Task", MitreTactic.PERSISTENCE),
    "T1490": ("Inhibit System Recovery", MitreTactic.IMPACT),
    "T1112": ("Modify Registry", MitreTactic.DEFENSE_EVASION),
    "T1547.001": ("Registry Run Keys / Startup Folder", MitreTactic.PERSISTENCE),
    "T1543.003": ("Windows Service", MitreTactic.PERSISTENCE),
    "T1082": ("System Information Discovery", MitreTactic.DISCOVERY),
    "T1087": ("Account Discovery", MitreTactic.DISCOVERY),
    "T1033": ("System Owner/User Discovery", MitreTactic.DISCOVERY),
    "T1016": ("System Network Configuration Discovery", MitreTactic.DISCOVERY),
    "T1083": ("File and Directory Discovery", MitreTactic.DISCOVERY),
    "T1564.001": ("Hidden Files and Directories", MitreTactic.DEFENSE_EVASION),
    "T1562.001": ("Disable or Modify Tools / Impair Defenses", MitreTactic.DEFENSE_EVASION),
    "T1070.001": ("Clear Windows Event Logs", MitreTactic.DEFENSE_EVASION),
    "T1070.004": ("File Deletion", MitreTactic.DEFENSE_EVASION),
    "T1027": ("Obfuscated Files or Information", MitreTactic.DEFENSE_EVASION),
    "T1027.004": ("Compile After Delivery", MitreTactic.DEFENSE_EVASION),
    "T1127.001": ("MSBuild", MitreTactic.DEFENSE_EVASION),
    "T1136": ("Create Account", MitreTactic.PERSISTENCE),
}


def get_mitre_mapping(technique_id: str) -> Optional[MitreAttackMapping]:
    """Retrieves MitreAttackMapping instance for a given technique ID."""
    entry = MITRE_CATALOG.get(technique_id)
    if entry:
        name, tactic = entry
        sub_id = technique_id if "." in technique_id else None
        return MitreAttackMapping(
            technique_id=technique_id,
            technique_name=name,
            tactic=tactic,
            subtechnique_id=sub_id,
        )
    return None


# =========================================================================
# 4. LOLBins & Malicious Execution Primitives Registry
# =========================================================================

# Mapping of LOLBin executable names (lowercase without .exe and with .exe) to primary MITRE technique ID
LOLBIN_REGISTRY: Dict[str, str] = {
    "certutil": "T1105",
    "certutil.exe": "T1105",
    "bitsadmin": "T1197",
    "bitsadmin.exe": "T1197",
    "powershell": "T1059.001",
    "powershell.exe": "T1059.001",
    "pwsh": "T1059.001",
    "pwsh.exe": "T1059.001",
    "mshta": "T1218.005",
    "mshta.exe": "T1218.005",
    "rundll32": "T1218.011",
    "rundll32.exe": "T1218.011",
    "regsvr32": "T1218.010",
    "regsvr32.exe": "T1218.010",
    "cscript": "T1059.005",
    "cscript.exe": "T1059.005",
    "wscript": "T1059.005",
    "wscript.exe": "T1059.005",
    "curl": "T1105",
    "curl.exe": "T1105",
    "wget": "T1105",
    "wget.exe": "T1105",
    "schtasks": "T1053.005",
    "schtasks.exe": "T1053.005",
    "at": "T1053.005",
    "at.exe": "T1053.005",
    "vssadmin": "T1490",
    "vssadmin.exe": "T1490",
    "wmic": "T1047",
    "wmic.exe": "T1047",
    "reg": "T1112",
    "reg.exe": "T1112",
    "sc": "T1543.003",
    "sc.exe": "T1543.003",
    "net": "T1087",
    "net.exe": "T1087",
    "net1": "T1087",
    "net1.exe": "T1087",
    "whoami": "T1033",
    "whoami.exe": "T1033",
    "systeminfo": "T1082",
    "systeminfo.exe": "T1082",
    "ipconfig": "T1016",
    "ipconfig.exe": "T1016",
    "findstr": "T1083",
    "findstr.exe": "T1083",
    "attrib": "T1564.001",
    "attrib.exe": "T1564.001",
    "taskkill": "T1562.001",
    "taskkill.exe": "T1562.001",
    "wevtutil": "T1070.001",
    "wevtutil.exe": "T1070.001",
    "bcdedit": "T1490",
    "bcdedit.exe": "T1490",
    "fsutil": "T1070.004",
    "fsutil.exe": "T1070.004",
    "hh": "T1218.001",
    "hh.exe": "T1218.001",
    "cmstp": "T1218.003",
    "cmstp.exe": "T1218.003",
    "installutil": "T1218.004",
    "installutil.exe": "T1218.004",
    "msbuild": "T1127.001",
    "msbuild.exe": "T1127.001",
    "csc": "T1027.004",
    "csc.exe": "T1027.004",
}


# Specific command argument behavior patterns for technique disambiguation
SUSPICIOUS_CMD_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # CertUtil decode vs download vs hashfile (decode checked first to avoid -f collision)
    (re.compile(r"(?i)\bcertutil(?:\.exe)?\s+.*(?:[/–-](?:decode|decodehex|encode))"), "T1140"),
    (re.compile(r"(?i)\bcertutil(?:\.exe)?\s+.*(?:[/–-](?:urlcache|split))"), "T1105"),
    (re.compile(r"(?i)\bcertutil(?:\.exe)?\s+.*[/–-]hashfile"), "T1027"),
    # Bitsadmin download
    (re.compile(r"(?i)\bbitsadmin(?:\.exe)?\s+.*(?:[/–-]transfer|[/–-]addfile|[/–-]resume)"), "T1197"),
    # Shadow copy & backup destruction
    (re.compile(r"(?i)\bvssadmin(?:\.exe)?\s+.*delete\s+shadow"), "T1490"),
    (re.compile(r"(?i)\bwmic(?:\.exe)?\s+.*shadowcopy\s+delete"), "T1490"),
    (re.compile(r"(?i)\bbcdedit(?:\.exe)?\s+.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"), "T1490"),
    # Event log clearing
    (re.compile(r"(?i)\bwevtutil(?:\.exe)?\s+.*(?:cl|clear-log)\s+"), "T1070.001"),
    # Registry Run Key persistence and defense impairment
    (re.compile(r"(?i)\breg(?:\.exe)?\s+add\s+.*(?:\\currentversion\\run|\\currentversion\\runonce)", re.IGNORECASE), "T1547.001"),
    (re.compile(r"(?i)\breg(?:\.exe)?\s+(?:delete|add)\s+.*(?:\\policies|\\windows\s+defender)", re.IGNORECASE), "T1562.001"),
    # Scheduled task creation
    (re.compile(r"(?i)\bschtasks(?:\.exe)?\s+.*(?:[/–-]create|[/–-]run)"), "T1053.005"),
    # PowerShell encoded commands or download primitives
    (re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\s+.*(?:-enc|-encodedcommand|-e\s+)"), "T1027"),
    (re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\s+.*(?:downloadstring|downloadfile|invoke-webrequest|iwr|curl|wget)"), "T1105"),
    # Regsvr32 scrobj.dll execution
    (re.compile(r"(?i)\bregsvr32(?:\.exe)?\s+.*(?:scrobj\.dll|/i:http)"), "T1218.010"),
    # Rundll32 invocation
    (re.compile(r"(?i)\brundll32(?:\.exe)?\s+"), "T1218.011"),
    # Mshta URL / script execution
    (re.compile(r"(?i)\bmshta(?:\.exe)?\s+.*(?:http|vbscript|javascript)"), "T1218.005"),
    # Net and Net1 service / user manipulation
    (re.compile(r"(?i)\b(?:net1?|sc)(?:\.exe)?\s+stop\s+.*(?:windefend|mpssvc|wuauserv|securitycenter)"), "T1562.001"),
    (re.compile(r"(?i)\bnet1?(?:\.exe)?\s+user\s+.*(?:[/–-]add)"), "T1136"),
]


# =========================================================================
# 5. Specialized Command-Line & Argument Extraction Regexes
# =========================================================================

# Match registry keys with support for quoted paths with spaces
REGISTRY_KEY_REGEX = re.compile(
    r"""(?i)(?:["']((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^"'\r\n\^]+)["']|\b((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\s"'/\^]+))"""
)

# PowerShell file drop extractors with quoted and unquoted path support
POWERSHELL_OUTFILE_REGEX = re.compile(
    r"""(?i)-outfile\s+(?:["']([^"']+)["']|([^\s\)]+))"""
)
POWERSHELL_DOWNLOADFILE_REGEX = re.compile(
    r"""(?i)\.downloadfile\s*\([^,]+,\s*["']([^"']+)["']\)"""
)

# Command argument tokenizer preserving quoted strings with whitespace
CMD_ARG_TOKEN_REGEX = re.compile(r'"[^"]*(?:"|$)|[^\s"]+')

