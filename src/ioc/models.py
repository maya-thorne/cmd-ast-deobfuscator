"""
Data models, enumerations, telemetry metrics, and defanging protocols for
AST-based Malware Indicator of Compromise (IOC) extraction.
"""

from dataclasses import dataclass, field
from enum import Enum
import json
import re
from typing import Any, Dict, List, Optional, Set


class IOCType(str, Enum):
    """Categorization of detected malware Indicators of Compromise (IOCs)."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    DOMAIN = "domain"
    FILE_DROP = "file_drop"
    FILE_PATH = "file_path"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    LOLBIN = "lolbin"
    REGISTRY_KEY = "registry_key"
    COMMAND_LINE = "command_line"
    EMAIL = "email"


class IOCSeverity(str, Enum):
    """Threat severity levels for extracted indicators."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MitreTactic(str, Enum):
    """MITRE ATT&CK enterprise tactics associated with batch script activities."""
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    DEFENSE_EVASION = "Defense Evasion"
    COMMAND_AND_CONTROL = "Command and Control"
    DISCOVERY = "Discovery"
    IMPACT = "Impact"
    LATERAL_MOVEMENT = "Lateral Movement"
    EXFILTRATION = "Exfiltration"
    INITIAL_ACCESS = "Initial Access"


@dataclass
class MitreAttackMapping:
    """Mapping of an indicator or behavior to a MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic: MitreTactic
    subtechnique_id: Optional[str] = None
    reference_url: str = ""

    def __post_init__(self):
        if not self.reference_url and self.technique_id:
            tid = self.technique_id.replace(".", "/")
            self.reference_url = f"https://attack.mitre.org/techniques/{tid}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic.value if isinstance(self.tactic, MitreTactic) else str(self.tactic),
            "subtechnique_id": self.subtechnique_id,
            "reference_url": self.reference_url,
        }


def defang_ipv4(ip: str) -> str:
    """Defangs an IPv4 address by bracket-escaping dots."""
    return re.sub(r"\.", "[.]", ip)


def defang_ipv6(ip: str) -> str:
    """Defangs an IPv6 address by bracket-escaping colons and embedded IPv4 dots."""
    res = re.sub(r":+", lambda m: "[::]" if len(m.group(0)) > 1 else "[:]", ip)
    if "." in res:
        res = re.sub(r"\.", "[.]", res)
    return res


def defang_domain(domain: str) -> str:
    """Defangs a domain or FQDN by bracket-escaping dots."""
    return re.sub(r"\.", "[.]", domain)


def defang_url(url: str) -> str:
    """Defangs a URL by replacing protocols (http->hxxp, ftp->fxp) and dots in host."""
    def _replace_proto(match: re.Match) -> str:
        proto = match.group(1).lower()
        if proto in ("http", "ws"):
            return "hxxp://"
        elif proto in ("https", "wss"):
            return "hxxps://"
        elif proto == "ftp":
            return "fxp://"
        elif proto == "sftp":
            return "sfxp://"
        return proto + "://"

    res = re.sub(r"^([a-zA-Z]+)://", _replace_proto, url)
    parts = res.split("/", 3)
    if len(parts) >= 3:
        host_port = parts[2]
        if "@" in host_port:
            user, host_port = host_port.split("@", 1)
            host_defanged = re.sub(r"\.", "[.]", host_port)
            parts[2] = f"{user}@{host_defanged}"
        else:
            parts[2] = re.sub(r"\.", "[.]", host_port)
        return "/".join(parts)
    return re.sub(r"\.", "[.]", res)


def defang_ioc(ioc_type: IOCType, value: str) -> str:
    """Defang an arbitrary IOC according to its type."""
    if ioc_type == IOCType.IPV4:
        return defang_ipv4(value)
    elif ioc_type == IOCType.IPV6:
        return defang_ipv6(value)
    elif ioc_type == IOCType.URL:
        return defang_url(value)
    elif ioc_type == IOCType.DOMAIN:
        return defang_domain(value)
    elif ioc_type == IOCType.EMAIL:
        return re.sub(r"@", "[at]", re.sub(r"\.", "[.]", value))
    return value


@dataclass
class IOCItem:
    """Represents a single extracted Indicator of Compromise (IOC)."""
    ioc_type: IOCType
    value: str
    defanged_value: str = ""
    context: str = ""
    line_number: Optional[int] = None
    confidence: float = 0.8
    severity: IOCSeverity = IOCSeverity.MEDIUM
    mitre_attack: Optional[MitreAttackMapping] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.defanged_value and self.value:
            self.defanged_value = defang_ioc(self.ioc_type, self.value)

    def defang(self) -> str:
        """Returns the defanged representation of this IOC."""
        if not self.defanged_value:
            self.defanged_value = defang_ioc(self.ioc_type, self.value)
        return self.defanged_value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.ioc_type.value,
            "value": self.value,
            "defanged_value": self.defanged_value,
            "context": self.context,
            "line_number": self.line_number,
            "confidence": round(self.confidence, 4),
            "severity": self.severity.value,
            "mitre_attack": self.mitre_attack.to_dict() if self.mitre_attack else None,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }

    def zeroize(self) -> None:
        """Securely zeroes in-memory string values and buffers."""
        if self.value:
            self.value = "\x00" * len(self.value)
        if self.defanged_value:
            self.defanged_value = "\x00" * len(self.defanged_value)
        if self.context:
            self.context = "\x00" * len(self.context)
        self.mitre_attack = None
        self.tags.clear()
        self.metadata.clear()


@dataclass
class IOCMetrics:
    """Quantitative telemetry metrics for IOC extraction."""
    total_iocs_found: int = 0
    unique_iocs: int = 0
    ips_found: int = 0
    urls_found: int = 0
    domains_found: int = 0
    files_dropped: int = 0
    lolbins_detected: int = 0
    hashes_found: int = 0
    mitre_techniques_matched: int = 0

    @classmethod
    def from_iocs(cls, iocs: List["IOCItem"]) -> "IOCMetrics":
        """Computes telemetry counters directly from an IOCItem collection."""
        unique_vals = {i.value for i in iocs}
        return cls(
            total_iocs_found=len(iocs),
            unique_iocs=len(unique_vals),
            ips_found=sum(1 for i in iocs if i.ioc_type in (IOCType.IPV4, IOCType.IPV6)),
            urls_found=sum(1 for i in iocs if i.ioc_type == IOCType.URL),
            domains_found=sum(1 for i in iocs if i.ioc_type == IOCType.DOMAIN),
            files_dropped=sum(1 for i in iocs if i.ioc_type == IOCType.FILE_DROP),
            lolbins_detected=sum(1 for i in iocs if i.ioc_type == IOCType.LOLBIN),
            hashes_found=sum(1 for i in iocs if i.ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256)),
            mitre_techniques_matched=len({i.mitre_attack.technique_id for i in iocs if i.mitre_attack}),
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            "total_iocs_found": self.total_iocs_found,
            "unique_iocs": self.unique_iocs,
            "ips_found": self.ips_found,
            "urls_found": self.urls_found,
            "domains_found": self.domains_found,
            "files_dropped": self.files_dropped,
            "lolbins_detected": self.lolbins_detected,
            "hashes_found": self.hashes_found,
            "mitre_techniques_matched": self.mitre_techniques_matched,
        }

    def summary(self) -> str:
        """Formats telemetry counters as human-readable summary string."""
        lines = [
            f"  Total IOCs found         : {self.total_iocs_found}",
            f"  Unique IOCs              : {self.unique_iocs}",
            f"  IP addresses found       : {self.ips_found}",
            f"  URLs found               : {self.urls_found}",
            f"  Domains found            : {self.domains_found}",
            f"  Dropped files/binaries   : {self.files_dropped}",
            f"  LOLBins detected         : {self.lolbins_detected}",
            f"  Hashes identified        : {self.hashes_found}",
            f"  MITRE techniques matched : {self.mitre_techniques_matched}",
        ]
        return "\n".join(lines)

    def zeroize(self) -> None:
        """Resets all telemetry counters to zero."""
        self.total_iocs_found = 0
        self.unique_iocs = 0
        self.ips_found = 0
        self.urls_found = 0
        self.domains_found = 0
        self.files_dropped = 0
        self.lolbins_detected = 0
        self.hashes_found = 0
        self.mitre_techniques_matched = 0


@dataclass
class IOCExtractionResult:
    """Consolidated outcome of AST and heuristic IOC extraction."""
    iocs: List[IOCItem] = field(default_factory=list)
    metrics: IOCMetrics = field(default_factory=IOCMetrics)
    source_file: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.metrics.total_iocs_found == 0 and self.iocs:
            self.metrics = IOCMetrics.from_iocs(self.iocs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_file": self.source_file,
            "metrics": self.metrics.to_dict(),
            "ioc_count": len(self.iocs),
            "iocs": [item.to_dict() for item in self.iocs],
            "metadata": dict(self.metadata),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes extraction result to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        """Serializes indicators into standard CSV table."""
        from .exporters import export_csv
        return export_csv(self)

    def to_markdown(self) -> str:
        """Formats extraction summary and indicator table as Markdown."""
        from .exporters import export_markdown
        return export_markdown(self)

    def to_stix_bundle(self) -> Dict[str, Any]:
        """Converts extraction outcome into OASIS STIX 2.1 Threat Intelligence Bundle."""
        from .exporters import export_stix_bundle
        return export_stix_bundle(self)

    def to_stix_json(self, indent: int = 2) -> str:
        """Serializes STIX 2.1 bundle to JSON string."""
        return json.dumps(self.to_stix_bundle(), indent=indent)

    def filter(
        self,
        ioc_types: Optional[List[IOCType]] = None,
        min_confidence: Optional[float] = None,
        mitre_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> "IOCExtractionResult":
        """Creates a filtered copy of the IOC extraction results."""
        filtered_iocs: List[IOCItem] = []
        target_types = set(ioc_types) if ioc_types else None
        target_tags = set(tags) if tags else None

        for item in self.iocs:
            if target_types and item.ioc_type not in target_types:
                continue
            if min_confidence is not None and item.confidence < min_confidence:
                continue
            if mitre_id:
                if not item.mitre_attack:
                    continue
                mid = mitre_id.strip().upper()
                tid = item.mitre_attack.technique_id.upper()
                if tid != mid and not tid.startswith(mid + "."):
                    continue
            if target_tags and not target_tags.intersection(item.tags):
                continue
            filtered_iocs.append(item)

        m = IOCMetrics.from_iocs(filtered_iocs)
        return IOCExtractionResult(
            iocs=filtered_iocs,
            metrics=m,
            source_file=self.source_file,
            metadata=dict(self.metadata),
        )

    def defang(self) -> "IOCExtractionResult":
        """Creates a copy of extraction results with all indicators defanged."""
        defanged_items: List[IOCItem] = []
        for item in self.iocs:
            d_val = item.defang()
            new_item = IOCItem(
                ioc_type=item.ioc_type,
                value=d_val,
                defanged_value=d_val,
                context=item.context,
                line_number=item.line_number,
                confidence=item.confidence,
                severity=item.severity,
                mitre_attack=item.mitre_attack,
                tags=list(item.tags),
                metadata=dict(item.metadata),
            )
            defanged_items.append(new_item)
        return IOCExtractionResult(
            iocs=defanged_items,
            metrics=self.metrics,
            source_file=self.source_file,
            metadata=dict(self.metadata),
        )

    def zeroize(self) -> None:
        """Cleanses all extracted indicators and resets metrics in memory."""
        for item in self.iocs:
            item.zeroize()
        self.iocs.clear()
        self.metrics.zeroize()
        self.metadata.clear()
        if self.source_file:
            self.source_file = "\x00" * len(self.source_file)
            self.source_file = None
