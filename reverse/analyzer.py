#!/usr/bin/env python3
"""
Advanced Reverse Engineering & Malware Analysis Tool
Supports: .bin, .dat, .exe, .dll (PE), ELF, .js, .vbs
Outputs: HTML report, JSON report, PDF-ready HTML
"""

import os
import sys
import json
import math
import re
import struct
import hashlib
import argparse
import datetime
import string
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Optional deps ──────────────────────────────────────────────────────────────
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    category: str          # EXPLOIT | MALWARE | SUSPICIOUS | INFO
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    description: str
    offset: Optional[int] = None
    data: Optional[str]   = None
    rule: Optional[str]   = None   # YARA rule name if applicable

@dataclass
class AnalysisReport:
    filename: str
    file_size: int
    file_type: str
    md5: str
    sha1: str
    sha256: str
    entropy: float
    timestamp: str
    findings: list = field(default_factory=list)
    disassembly: list = field(default_factory=list)
    strings_extracted: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    exports: list = field(default_factory=list)
    sections: list = field(default_factory=list)
    yara_matches: list = field(default_factory=list)
    score: int = 0           # 0-100 risk score
    verdict: str = "CLEAN"   # CLEAN | SUSPICIOUS | MALWARE

# ── Helpers ───────────────────────────────────────────────────────────────────

SEVERITY_WEIGHT = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0}

def compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total  = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c)

def detect_file_type(data: bytes, filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if data[:2] == b'MZ':
        return "PE"
    if data[:4] == b'\x7fELF':
        return "ELF"
    if ext in ('.js',):
        return "JavaScript"
    if ext in ('.vbs',):
        return "VBScript"
    if ext in ('.bin', '.dat', ''):
        return "Shellcode/Raw"
    try:
        data.decode('utf-8')
        return "Text/Script"
    except Exception:
        return "Binary/Unknown"

def extract_strings(data: bytes, min_len: int = 5) -> list:
    """Extract both ASCII and wide strings."""
    results = []
    # ASCII
    ascii_pat = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')
    for m in ascii_pat.finditer(data):
        results.append({"type": "ASCII", "offset": m.start(), "value": m.group().decode('ascii', errors='replace')})
    # Wide (UTF-16 LE)
    wide_pat = re.compile(rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}')
    for m in wide_pat.finditer(data):
        try:
            s = m.group().decode('utf-16-le', errors='replace').strip('\x00')
            if s.isprintable():
                results.append({"type": "WIDE", "offset": m.start(), "value": s})
        except Exception:
            pass
    return results[:500]  # cap

# ── Static Analysis ───────────────────────────────────────────────────────────

class StaticAnalyzer:

    SUSPICIOUS_STRINGS = {
        # Network & C2
        r'(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})': ("C2/IP URL", "HIGH"),
        r'(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe)': ("Shell Invocation", "HIGH"),
        r'(WinExec|ShellExecute|CreateProcess)': ("Process Creation API", "HIGH"),
        r'(VirtualAlloc|VirtualProtect|WriteProcessMemory)': ("Memory Manipulation API", "CRITICAL"),
        r'(NtCreateThread|CreateRemoteThread|RtlCreateUserThread)': ("Remote Thread Injection", "CRITICAL"),
        r'(LoadLibrary|GetProcAddress)': ("Dynamic Import Resolution", "MEDIUM"),
        # Obfuscation
        r'(eval\s*\(|document\.write\s*\()': ("JS Eval/Write Sink", "HIGH"),
        r'(fromCharCode|atob\s*\(|btoa\s*\()': ("Encoding/Obfuscation Primitive", "MEDIUM"),
        r'(ActiveXObject|WScript\.Shell|Shell\.Application)': ("COM/Shell Object", "CRITICAL"),
        r'(base64_decode|base64_encode)': ("Base64 Routine", "LOW"),
        # Ransomware / crypto
        r'(CryptEncrypt|CryptGenKey|BCryptEncrypt)': ("Crypto API (Ransomware?)", "HIGH"),
        r'(DeleteShadowCopy|vssadmin|bcdedit|wbadmin)': ("Shadow Copy Deletion", "CRITICAL"),
        # Persistence
        r'(HKEY_LOCAL_MACHINE|HKCU|CurrentVersion\\Run)': ("Registry Persistence Key", "HIGH"),
        r'(schtasks|at\.exe|AddJob)': ("Task Scheduler Abuse", "HIGH"),
        r'(StartupFolder|Startup)': ("Startup Folder Reference", "MEDIUM"),
        # Shellcode patterns
        r'(\xfc\xe8|\x55\x8b\xec|\x64\x8b\x35)': ("Shellcode Prologue Bytes", "CRITICAL"),
        # Network
        r'(WSAStartup|socket|connect|send|recv|InternetOpen)': ("Network API", "MEDIUM"),
        r'(URLDownloadToFile|HttpSendRequest|WinHttpOpen)': ("HTTP Download API", "HIGH"),
    }

    EXPLOIT_PATTERNS = [
        (rb'\x0a\x0d' * 20, "Egg Hunter / Heap Spray Padding", "HIGH"),
        (rb'\x90' * 16, "NOP Sled (shellcode)", "CRITICAL"),
        (rb'\xcc' * 4, "INT3 Breakpoint Sled (anti-debug)", "MEDIUM"),
        (rb'\x41' * 50, "Pattern Buffer (fuzzing/BoF)", "HIGH"),
        (rb'\x42' * 50, "Pattern Buffer (fuzzing/BoF)", "HIGH"),
    ]

    def analyze(self, data: bytes, report: AnalysisReport):
        self._check_entropy(data, report)
        self._check_strings(data, report)
        self._check_binary_patterns(data, report)

    def _check_entropy(self, data: bytes, report: AnalysisReport):
        e = report.entropy
        if e > 7.2:
            report.findings.append(Finding(
                "SUSPICIOUS", "HIGH",
                "Very High Entropy Detected",
                f"Entropy={e:.4f} — likely packed, encrypted, or compressed payload.",
                data=f"{e:.4f}"
            ))
        elif e > 6.5:
            report.findings.append(Finding(
                "SUSPICIOUS", "MEDIUM",
                "Elevated Entropy",
                f"Entropy={e:.4f} — possible obfuscated content.",
                data=f"{e:.4f}"
            ))

    def _check_strings(self, data: bytes, report: AnalysisReport):
        text = data.decode('latin-1')
        for pattern, (title, sev) in self.SUSPICIOUS_STRINGS.items():
            try:
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    report.findings.append(Finding(
                        "MALWARE" if sev in ("CRITICAL","HIGH") else "SUSPICIOUS",
                        sev, title,
                        f"Pattern match: '{m.group()[:120]}'",
                        offset=m.start(),
                        data=m.group()[:120]
                    ))
            except Exception:
                pass

    def _check_binary_patterns(self, data: bytes, report: AnalysisReport):
        for pattern, title, sev in self.EXPLOIT_PATTERNS:
            idx = data.find(pattern)
            if idx != -1:
                report.findings.append(Finding(
                    "EXPLOIT", sev, title,
                    f"Found at offset 0x{idx:08X}",
                    offset=idx,
                    data=data[idx:idx+32].hex()
                ))

# ── PE Analyzer ───────────────────────────────────────────────────────────────

class PEAnalyzer:

    SUSPICIOUS_IMPORTS = {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",  # keylogger
        "CryptEncrypt", "CryptGenKey", "BCryptEncrypt",
        "InternetOpen", "URLDownloadToFile", "HttpSendRequest",
        "WinExec", "ShellExecuteA", "ShellExecuteW",
        "RegSetValueEx", "RegCreateKeyEx",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",  # anti-debug
        "NtQueryInformationProcess",
    }

    def analyze(self, data: bytes, report: AnalysisReport):
        if not HAS_PEFILE:
            report.findings.append(Finding("INFO", "INFO",
                "pefile not installed",
                "Install with: pip install pefile"))
            return
        try:
            pe = pefile.PE(data=data)
            self._parse_sections(pe, report)
            self._parse_imports(pe, report)
            self._parse_exports(pe, report)
            self._check_pe_flags(pe, report)
        except Exception as ex:
            report.findings.append(Finding("INFO","INFO","PE Parse Error", str(ex)))

    def _parse_sections(self, pe, report: AnalysisReport):
        for s in pe.sections:
            name = s.Name.decode('utf-8', errors='replace').strip('\x00')
            ent  = compute_entropy(s.get_data())
            flags = s.Characteristics
            is_wx = bool(flags & 0x20000000) and bool(flags & 0x40000000)
            report.sections.append({
                "name": name, "vaddr": hex(s.VirtualAddress),
                "vsize": s.Misc_VirtualSize, "rsize": s.SizeOfRawData,
                "entropy": round(ent, 4), "wx": is_wx
            })
            if ent > 7.0:
                report.findings.append(Finding("SUSPICIOUS","HIGH",
                    f"High-entropy section: {name}",
                    f"Entropy={ent:.4f} — packed/encrypted code possible."))
            if is_wx:
                report.findings.append(Finding("EXPLOIT","CRITICAL",
                    f"W+X section: {name}",
                    "Section is both Writable and Executable — classic shellcode injection target."))

    def _parse_imports(self, pe, report: AnalysisReport):
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='replace')
            for imp in entry.imports:
                if not imp.name:
                    continue
                name = imp.name.decode('utf-8', errors='replace')
                report.imports.append({"dll": dll, "function": name})
                if name in self.SUSPICIOUS_IMPORTS:
                    report.findings.append(Finding("MALWARE","HIGH",
                        f"Suspicious Import: {name}",
                        f"From {dll} — associated with malicious behavior."))

    def _parse_exports(self, pe, report: AnalysisReport):
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                report.exports.append(exp.name.decode('utf-8', errors='replace'))

    def _check_pe_flags(self, pe, report: AnalysisReport):
        # Check compile timestamp
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts == 0 or ts == 0xFFFFFFFF:
            report.findings.append(Finding("SUSPICIOUS","MEDIUM",
                "Invalid PE Timestamp",
                "Timestamp is zeroed or maxed — likely tampered."))
        # Check for no imports (packed)
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            report.findings.append(Finding("SUSPICIOUS","HIGH",
                "No Import Table",
                "PE has no imports — likely packed/obfuscated."))

# ── ELF Analyzer ──────────────────────────────────────────────────────────────

class ELFAnalyzer:

    SUSPICIOUS_SYMBOLS = [
        "system", "execve", "execvp", "popen", "fork",
        "ptrace", "mprotect", "mmap", "dlopen", "dlsym",
        "socket", "connect", "recv", "send",
        "setuid", "setgid", "getpwuid",
    ]

    def analyze(self, data: bytes, report: AnalysisReport):
        if len(data) < 64:
            return
        self._parse_header(data, report)
        self._parse_strings_for_symbols(data, report)

    def _parse_header(self, data: bytes, report: AnalysisReport):
        ei_class = data[4]
        bits = {1: "32-bit", 2: "64-bit"}.get(ei_class, "Unknown")
        ei_data  = data[5]
        endian   = {1: "Little Endian", 2: "Big Endian"}.get(ei_data, "Unknown")
        e_type   = struct.unpack_from('<H', data, 16)[0]
        types    = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
        report.findings.append(Finding("INFO","INFO","ELF Header",
            f"Class={bits}, Endian={endian}, Type={types.get(e_type,'?')}"))
        if e_type == 3:
            report.findings.append(Finding("SUSPICIOUS","LOW",
                "ELF Shared Object (ET_DYN)",
                "Could be a shared library injected into processes."))

    def _parse_strings_for_symbols(self, data: bytes, report: AnalysisReport):
        ascii_strings = re.findall(rb'[ -~]{4,}', data)
        for s in ascii_strings:
            dec = s.decode('ascii', errors='replace')
            for sym in self.SUSPICIOUS_SYMBOLS:
                if sym == dec.strip():
                    report.findings.append(Finding("MALWARE","MEDIUM",
                        f"Suspicious Symbol: {sym}",
                        f"Symbol '{sym}' linked — associated with exploitation or privilege escalation."))
                    break

# ── Script Analyzer ───────────────────────────────────────────────────────────

class ScriptAnalyzer:

    JS_PATTERNS = [
        (r'eval\s*\(', "eval() Sink", "HIGH"),
        (r'document\.write\s*\(', "document.write() Sink", "HIGH"),
        (r'atob\s*\(|btoa\s*\(', "Base64 Decode/Encode", "MEDIUM"),
        (r'fromCharCode', "Char-code Obfuscation", "MEDIUM"),
        (r'unescape\s*\(', "unescape() Obfuscation", "MEDIUM"),
        (r'new\s+Function\s*\(', "Dynamic Function Construction", "CRITICAL"),
        (r'setTimeout\s*\(\s*["\']', "String-based setTimeout", "HIGH"),
        (r'XMLHttpRequest|fetch\s*\(', "HTTP Request", "MEDIUM"),
        (r'window\.location\s*=', "Redirect", "MEDIUM"),
        (r'__proto__|prototype\.constructor', "Prototype Pollution", "HIGH"),
        (r'require\s*\(\s*[\'"]child_process', "Node child_process", "CRITICAL"),
        (r'require\s*\(\s*[\'"]fs', "Node fs module", "LOW"),
    ]

    VBS_PATTERNS = [
        (r'WScript\.Shell', "WScript.Shell COM Object", "CRITICAL"),
        (r'Shell\.Application', "Shell.Application COM", "CRITICAL"),
        (r'ActiveXObject', "ActiveX Object", "HIGH"),
        (r'CreateObject', "CreateObject Call", "HIGH"),
        (r'Environ\s*\(', "Environment Variable Read", "MEDIUM"),
        (r'GetObject\s*\(', "GetObject (WMI?)", "HIGH"),
        (r'ADODB\.Stream', "ADODB.Stream (file write)", "CRITICAL"),
        (r'chr\s*\(\d+\)\s*&', "Chr() Obfuscation", "MEDIUM"),
        (r'Execute\s*\(', "Execute() Call", "HIGH"),
    ]

    def analyze(self, data: bytes, report: AnalysisReport):
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = data.decode('latin-1')

        patterns = self.VBS_PATTERNS if report.file_type == "VBScript" else self.JS_PATTERNS
        for pattern, title, sev in patterns:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                line_no = text[:m.start()].count('\n') + 1
                report.findings.append(Finding(
                    "MALWARE" if sev in ("CRITICAL","HIGH") else "SUSPICIOUS",
                    sev, title,
                    f"Line {line_no}: ...{text[max(0,m.start()-20):m.end()+40].strip()[:120]}...",
                    offset=m.start()
                ))

        # Obfuscation detection: long single-line blobs
        lines = text.split('\n')
        for i, line in enumerate(lines):
            if len(line) > 500:
                report.findings.append(Finding("SUSPICIOUS","HIGH",
                    f"Extremely Long Line (line {i+1})",
                    f"Length={len(line)} chars — common obfuscation technique.",
                    offset=i))

# ── YARA Engine ───────────────────────────────────────────────────────────────

class YARAEngine:

    BUILTIN_RULES = r"""
rule Shellcode_NOP_Sled {
    meta: description = "NOP sled detected" severity = "CRITICAL"
    strings: $nop = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition: $nop
}

rule Shellcode_Metasploit_Prologue {
    meta: description = "Metasploit shellcode prologue" severity = "CRITICAL"
    strings:
        $p1 = { fc e8 [1-4] 00 00 00 }
        $p2 = { 60 89 e5 31 d2 }
        $p3 = { 64 8b 52 30 }
    condition: any of them
}

rule PE_Packer_UPX {
    meta: description = "UPX packed executable" severity = "MEDIUM"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition: 2 of them
}

rule PE_MPRESS {
    meta: description = "MPRESS packer detected" severity = "MEDIUM"
    strings: $mp = "MPRESS1" ascii
    condition: $mp
}

rule Ransomware_ShadowCopy_Delete {
    meta: description = "Shadow copy deletion (ransomware behavior)" severity = "CRITICAL"
    strings:
        $s1 = "vssadmin" nocase ascii wide
        $s2 = "delete shadows" nocase ascii wide
        $s3 = "bcdedit" nocase ascii wide
        $s4 = "recoveryenabled no" nocase ascii wide
    condition: 2 of them
}

rule Persistence_Registry_Run {
    meta: description = "Registry Run key persistence" severity = "HIGH"
    strings:
        $r1 = "CurrentVersion\\Run" nocase wide ascii
        $r2 = "CurrentVersion\\RunOnce" nocase wide ascii
    condition: any of them
}

rule Keylogger_API {
    meta: description = "Keylogger API usage" severity = "HIGH"
    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "GetKeyboardState" ascii
        $k3 = "SetWindowsHookEx" ascii
    condition: any of them
}

rule Process_Injection_Classic {
    meta: description = "Classic process injection pattern" severity = "CRITICAL"
    strings:
        $v = "VirtualAllocEx" ascii
        $w = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition: 2 of them
}

rule AntiDebug_Checks {
    meta: description = "Anti-debugging techniques" severity = "MEDIUM"
    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "NtQueryInformationProcess" ascii
        $a4 = "OutputDebugString" ascii
    condition: 2 of them
}

rule VBS_Dropper {
    meta: description = "VBScript dropper pattern" severity = "CRITICAL"
    strings:
        $w = "WScript.Shell" nocase ascii wide
        $a = "ADODB.Stream" nocase ascii wide
        $c = "CreateObject" nocase ascii wide
    condition: $w and ($a or $c)
}

rule JS_Obfuscation_Heavy {
    meta: description = "Heavily obfuscated JavaScript" severity = "HIGH"
    strings:
        $e = "eval(" ascii
        $f = "fromCharCode" ascii
        $a = "atob(" ascii
    condition: 2 of them
}

rule Mimikatz_Strings {
    meta: description = "Mimikatz credential dumper strings" severity = "CRITICAL"
    strings:
        $m1 = "mimikatz" nocase ascii wide
        $m2 = "sekurlsa" nocase ascii
        $m3 = "lsadump" nocase ascii
        $m4 = "privilege::debug" nocase ascii
    condition: any of them
}

rule Cobalt_Strike_Beacon {
    meta: description = "Cobalt Strike beacon patterns" severity = "CRITICAL"
    strings:
        $cs1 = { 69 68 69 68 69 6b }
        $cs2 = "ReflectiveLoader" ascii
        $cs3 = "%s as %s\\%s" ascii
        $cs4 = "beacon.dll" nocase ascii
    condition: any of them
}

rule ELF_Backdoor_Symbols {
    meta: description = "ELF with backdoor-like exported symbols" severity = "HIGH"
    strings:
        $s1 = "reverse_shell" ascii
        $s2 = "bind_shell" ascii
        $s3 = "backdoor" nocase ascii
    condition: any of them
}

rule Generic_Base64_Blob {
    meta: description = "Large base64-encoded payload" severity = "MEDIUM"
    strings:
        $b = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii
    condition: $b
}
"""

    def analyze(self, data: bytes, report: AnalysisReport, extra_rules_path: Optional[str] = None):
        if not HAS_YARA:
            report.findings.append(Finding("INFO","INFO",
                "yara-python not installed",
                "Install with: pip install yara-python"))
            return
        try:
            rules_source = self.BUILTIN_RULES
            if extra_rules_path and os.path.isfile(extra_rules_path):
                with open(extra_rules_path, 'r') as f:
                    rules_source += "\n" + f.read()
            rules = yara.compile(source=rules_source)
            matches = rules.match(data=data)
            for m in matches:
                sev = m.meta.get('severity', 'MEDIUM')
                desc = m.meta.get('description', m.rule)
                report.yara_matches.append({"rule": m.rule, "description": desc, "severity": sev})
                report.findings.append(Finding(
                    "MALWARE", sev, f"YARA: {m.rule}", desc, rule=m.rule))
        except Exception as ex:
            report.findings.append(Finding("INFO","INFO","YARA Error", str(ex)))

# ── Disassembler ──────────────────────────────────────────────────────────────

class Disassembler:

    def disassemble(self, data: bytes, file_type: str, report: AnalysisReport, max_insn: int = 200):
        if not HAS_CAPSTONE:
            report.findings.append(Finding("INFO","INFO",
                "capstone not installed",
                "Install with: pip install capstone"))
            return
        try:
            import capstone as cs
            if file_type == "ELF":
                bits = data[4]
                md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if bits == 2 else cs.CS_MODE_32)
            else:
                # Default: x86-64
                md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
            md.detail = False
            offset = self._find_code_start(data, file_type)
            for insn in md.disasm(data[offset:], offset):
                report.disassembly.append({
                    "address": f"0x{insn.address:08X}",
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex()
                })
                if len(report.disassembly) >= max_insn:
                    break
        except Exception as ex:
            report.findings.append(Finding("INFO","INFO","Disassembly Error", str(ex)))

    def _find_code_start(self, data: bytes, file_type: str) -> int:
        if file_type == "PE" and len(data) > 0x40:
            try:
                pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
                if pe_offset + 0x18 < len(data):
                    ep = struct.unpack_from('<I', data, pe_offset + 0x28)[0]
                    return min(ep, len(data) - 1)
            except Exception:
                pass
        return 0

# ── Score & Verdict ───────────────────────────────────────────────────────────

def compute_verdict(report: AnalysisReport):
    score = 0
    for f in report.findings:
        score += SEVERITY_WEIGHT.get(f.severity, 0)
    # YARA bonus
    score += len(report.yara_matches) * 15
    # Entropy bonus
    if report.entropy > 7.2:
        score += 15
    report.score = min(score, 100)
    if report.score >= 60:
        report.verdict = "MALWARE"
    elif report.score >= 25:
        report.verdict = "SUSPICIOUS"
    else:
        report.verdict = "CLEAN"

# ── Report Writers ────────────────────────────────────────────────────────────

def write_json(report: AnalysisReport, out_path: str):
    data = asdict(report)
    data['findings'] = [asdict(f) for f in report.findings]
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)

def write_html(report: AnalysisReport, out_path: str):
    verdict_colors = {
        "CLEAN": ("#00ff88", "#0a1a10"),
        "SUSPICIOUS": ("#ffcc00", "#1a1600"),
        "MALWARE": ("#ff2244", "#1a0008"),
    }
    vc, vbg = verdict_colors.get(report.verdict, ("#aaa", "#111"))

    sev_badge = {
        "CRITICAL": "background:#ff2244;color:#fff",
        "HIGH":     "background:#ff6600;color:#fff",
        "MEDIUM":   "background:#ffcc00;color:#000",
        "LOW":      "background:#33aaff;color:#fff",
        "INFO":     "background:#555;color:#eee",
    }
    cat_icon = {
        "EXPLOIT":    "💣",
        "MALWARE":    "🦠",
        "SUSPICIOUS": "⚠️",
        "INFO":       "ℹ️",
    }

    def badge(sev):
        st = sev_badge.get(sev, "background:#333;color:#eee")
        return f'<span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;{st}">{sev}</span>'

    findings_html = ""
    for i, f in enumerate(report.findings):
        icon = cat_icon.get(f.category, "•")
        findings_html += f"""
        <div class="finding-card sev-{f.severity.lower()}">
          <div class="finding-header">
            <span class="finding-icon">{icon}</span>
            <span class="finding-title">{f.title}</span>
            {badge(f.severity)}
            <span class="cat-tag">{f.category}</span>
          </div>
          <div class="finding-body">
            <p>{f.description}</p>
            {"<code class='offset'>Offset: 0x"+f"{f.offset:08X}"+"</code>" if f.offset is not None else ""}
            {"<code class='data-hex'>"+f.data+"</code>" if f.data else ""}
            {"<span class='yara-tag'>YARA: "+f.rule+"</span>" if f.rule else ""}
          </div>
        </div>"""

    disasm_rows = ""
    for insn in report.disassembly[:200]:
        disasm_rows += f"""<tr>
          <td class="addr">{insn['address']}</td>
          <td class="bytes">{insn['bytes']}</td>
          <td class="mnem">{insn['mnemonic']}</td>
          <td class="ops">{insn['op_str']}</td>
        </tr>"""

    imports_html = ""
    for imp in report.imports[:100]:
        flag = "⚠️ " if any(s in imp['function'] for s in ["VirtualAlloc","CreateRemote","WriteProcess","CryptEncrypt","URLDownload","ShellExecute","GetProcAddress"]) else ""
        imports_html += f'<div class="import-row">{flag}<b>{imp["dll"]}</b> → <code>{imp["function"]}</code></div>'

    sections_html = ""
    for sec in report.sections:
        wx_warn = ' <span class="wx-badge">W+X ⚠</span>' if sec.get('wx') else ''
        entropy_color = "#ff4444" if sec['entropy'] > 7.0 else ("#ffaa00" if sec['entropy'] > 6.0 else "#44ff88")
        sections_html += f"""
        <tr>
          <td>{sec['name']}{wx_warn}</td>
          <td>{sec['vaddr']}</td>
          <td>{sec['vsize']}</td>
          <td style="color:{entropy_color};font-weight:700">{sec['entropy']}</td>
        </tr>"""

    strings_html = ""
    for s in report.strings_extracted[:100]:
        strings_html += f'<tr><td class="addr">0x{s["offset"]:08X}</td><td><span class="str-type">{s["type"]}</span></td><td><code>{s["value"][:120]}</code></td></tr>'

    yara_html = ""
    for m in report.yara_matches:
        yara_html += f'<div class="yara-hit">{badge(m["severity"])} <b>{m["rule"]}</b> — {m["description"]}</div>'

    crit = sum(1 for f in report.findings if f.severity == "CRITICAL")
    high = sum(1 for f in report.findings if f.severity == "HIGH")
    med  = sum(1 for f in report.findings if f.severity == "MEDIUM")
    low  = sum(1 for f in report.findings if f.severity == "LOW")

    score_color = "#ff2244" if report.score >= 60 else ("#ffcc00" if report.score >= 25 else "#00ff88")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Malware Analyzer — {report.filename}</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;900&display=swap" rel="stylesheet">
<style>
:root {{
  --bg: #050a0f;
  --surface: #0c1520;
  --surface2: #111d2e;
  --border: #1a3050;
  --accent: #00aaff;
  --accent2: #0066cc;
  --text: #c8ddf0;
  --muted: #4a6a8a;
  --mono: 'Share Tech Mono', monospace;
  --sans: 'Exo 2', sans-serif;
}}
*, *::before, *::after {{ box-sizing: border-box; margin:0; padding:0; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-weight: 300;
  min-height: 100vh;
  background-image:
    radial-gradient(ellipse 80% 40% at 50% 0%, rgba(0,100,200,0.08) 0%, transparent 70%),
    repeating-linear-gradient(0deg, transparent, transparent 40px, rgba(0,80,160,0.03) 40px, rgba(0,80,160,0.03) 41px),
    repeating-linear-gradient(90deg, transparent, transparent 40px, rgba(0,80,160,0.03) 40px, rgba(0,80,160,0.03) 41px);
}}
/* ── Header ── */
.header {{
  display: grid;
  grid-template-columns: 1fr auto;
  align-items: center;
  padding: 32px 48px 24px;
  border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, rgba(0,100,200,0.06) 0%, transparent 100%);
}}
.logo {{
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: 4px;
  color: var(--accent);
  text-transform: uppercase;
  margin-bottom: 8px;
  opacity: 0.7;
}}
.header h1 {{
  font-family: var(--sans);
  font-weight: 900;
  font-size: 28px;
  color: #fff;
  letter-spacing: -0.5px;
}}
.header h1 span {{ color: var(--accent); }}
.timestamp {{
  font-family: var(--mono);
  font-size: 11px;
  color: var(--muted);
  text-align: right;
}}
/* ── Verdict Banner ── */
.verdict-banner {{
  display: flex;
  align-items: center;
  gap: 24px;
  padding: 24px 48px;
  background: {vbg};
  border-bottom: 2px solid {vc}44;
  animation: scanline 4s linear infinite;
}}
@keyframes scanline {{
  0%,100% {{ box-shadow: inset 0 0 0 rgba(0,0,0,0); }}
  50% {{ box-shadow: inset 0 -1px 0 {vc}22; }}
}}
.verdict-label {{
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: 3px;
  color: {vc}aa;
  text-transform: uppercase;
}}
.verdict-value {{
  font-family: var(--sans);
  font-weight: 900;
  font-size: 48px;
  color: {vc};
  line-height: 1;
  text-shadow: 0 0 30px {vc}66;
}}
.score-ring {{
  margin-left: auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}}
.score-num {{
  font-family: var(--mono);
  font-size: 36px;
  font-weight: 700;
  color: {score_color};
  text-shadow: 0 0 20px {score_color}66;
}}
.score-label {{
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 2px;
  color: var(--muted);
}}
.stats-row {{
  display: flex;
  gap: 16px;
}}
.stat {{
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 8px 16px;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: 6px;
}}
.stat-num {{ font-family: var(--mono); font-size: 20px; font-weight: 700; }}
.stat-lab {{ font-family: var(--mono); font-size: 9px; letter-spacing: 2px; color: var(--muted); }}
.stat-crit .stat-num {{ color: #ff2244; }}
.stat-high .stat-num {{ color: #ff6600; }}
.stat-med  .stat-num {{ color: #ffcc00; }}
.stat-low  .stat-num {{ color: #33aaff; }}
/* ── Layout ── */
.main {{ padding: 32px 48px; display: flex; flex-direction: column; gap: 32px; }}
/* ── Section ── */
.section {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
}}
.section-header {{
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 20px;
  background: var(--surface2);
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  user-select: none;
}}
.section-header h2 {{
  font-family: var(--sans);
  font-weight: 600;
  font-size: 14px;
  letter-spacing: 1px;
  color: #fff;
  text-transform: uppercase;
}}
.section-icon {{ font-size: 18px; }}
.toggle-btn {{
  margin-left: auto;
  font-family: var(--mono);
  font-size: 16px;
  color: var(--muted);
  transition: transform 0.2s;
}}
.section-body {{ padding: 20px; }}
/* ── File Info Grid ── */
.info-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
}}
.info-cell {{
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 16px;
}}
.info-label {{
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 3px;
  color: var(--muted);
  text-transform: uppercase;
  margin-bottom: 4px;
}}
.info-value {{
  font-family: var(--mono);
  font-size: 13px;
  color: var(--accent);
  word-break: break-all;
}}
/* ── Entropy Bar ── */
.entropy-bar-wrap {{
  margin-top: 6px;
  background: rgba(0,0,0,0.4);
  border-radius: 4px;
  height: 6px;
  overflow: hidden;
}}
.entropy-bar {{
  height: 100%;
  border-radius: 4px;
  background: linear-gradient(90deg, #00ff88, #ffcc00, #ff2244);
  transition: width 1s ease;
}}
/* ── Findings ── */
.finding-card {{
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 10px;
  overflow: hidden;
  transition: border-color 0.2s;
}}
.finding-card:hover {{ border-color: var(--accent)55; }}
.finding-card.sev-critical {{ border-left: 3px solid #ff2244; }}
.finding-card.sev-high     {{ border-left: 3px solid #ff6600; }}
.finding-card.sev-medium   {{ border-left: 3px solid #ffcc00; }}
.finding-card.sev-low      {{ border-left: 3px solid #33aaff; }}
.finding-card.sev-info     {{ border-left: 3px solid #555; }}
.finding-header {{
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  background: var(--surface2);
  flex-wrap: wrap;
}}
.finding-icon {{ font-size: 16px; }}
.finding-title {{ font-weight: 600; font-size: 13px; flex: 1; }}
.cat-tag {{
  font-family: var(--mono);
  font-size: 10px;
  color: var(--muted);
  letter-spacing: 1px;
}}
.finding-body {{
  padding: 10px 14px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--text);
}}
.finding-body p {{ margin-bottom: 6px; }}
code.offset {{
  font-family: var(--mono);
  font-size: 11px;
  color: #00aaff;
  background: rgba(0,100,200,0.1);
  padding: 1px 6px;
  border-radius: 3px;
  margin-right: 8px;
}}
code.data-hex {{
  display: block;
  font-family: var(--mono);
  font-size: 11px;
  color: #aaa;
  background: rgba(0,0,0,0.3);
  padding: 4px 8px;
  border-radius: 4px;
  margin-top: 4px;
  word-break: break-all;
}}
.yara-tag {{
  display: inline-block;
  font-family: var(--mono);
  font-size: 10px;
  background: rgba(180,0,255,0.15);
  border: 1px solid rgba(180,0,255,0.3);
  color: #cc88ff;
  padding: 1px 6px;
  border-radius: 3px;
  margin-top: 4px;
}}
/* ── Tables ── */
table {{ width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; }}
th {{
  text-align: left;
  padding: 8px 12px;
  background: var(--surface2);
  color: var(--muted);
  letter-spacing: 2px;
  font-size: 10px;
  text-transform: uppercase;
  border-bottom: 1px solid var(--border);
}}
td {{ padding: 6px 12px; border-bottom: 1px solid rgba(26,48,80,0.5); }}
tr:hover td {{ background: rgba(0,100,200,0.05); }}
td.addr {{ color: var(--accent); }}
td.bytes {{ color: #556677; }}
td.mnem {{ color: #ff9944; font-weight: 700; }}
td.ops  {{ color: #88ccff; }}
.wx-badge {{
  font-size: 10px;
  background: rgba(255,34,68,0.15);
  border: 1px solid rgba(255,34,68,0.3);
  color: #ff6688;
  padding: 1px 5px;
  border-radius: 3px;
}}
/* ── Imports ── */
.import-row {{
  font-family: var(--mono);
  font-size: 12px;
  padding: 5px 8px;
  border-bottom: 1px solid var(--border)66;
  color: var(--text);
}}
.import-row:hover {{ background: rgba(0,100,200,0.05); }}
/* ── YARA ── */
.yara-hit {{
  padding: 8px 12px;
  border: 1px solid rgba(180,0,255,0.2);
  border-radius: 6px;
  margin-bottom: 8px;
  background: rgba(180,0,255,0.05);
  font-size: 13px;
}}
/* ── Strings ── */
.str-type {{
  font-family: var(--mono);
  font-size: 9px;
  background: rgba(0,100,200,0.15);
  color: var(--accent);
  padding: 1px 4px;
  border-radius: 2px;
}}
/* ── No findings ── */
.empty-state {{
  text-align: center;
  color: var(--muted);
  font-family: var(--mono);
  padding: 32px;
  font-size: 13px;
}}
/* ── Filter bar ── */
.filter-bar {{
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}}
.filter-btn {{
  font-family: var(--mono);
  font-size: 11px;
  padding: 4px 12px;
  border: 1px solid var(--border);
  background: var(--surface2);
  color: var(--text);
  border-radius: 20px;
  cursor: pointer;
  transition: all 0.2s;
  letter-spacing: 1px;
}}
.filter-btn:hover, .filter-btn.active {{ border-color: var(--accent); color: var(--accent); }}
/* ── Print / PDF ── */
@media print {{
  .toggle-btn, .filter-bar {{ display: none; }}
  .section-body {{ display: block !important; }}
  body {{ background: #fff; color: #000; }}
  .verdict-value {{ color: #000; }}
}}
/* ── Scrollbar ── */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg); }}
::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="logo">⬡ Malware Analysis Platform</div>
    <h1>Report: <span>{report.filename}</span></h1>
  </div>
  <div class="timestamp">
    {report.timestamp}<br>
    <span style="color:var(--accent)">{report.file_type}</span> · {report.file_size:,} bytes
  </div>
</div>

<div class="verdict-banner">
  <div>
    <div class="verdict-label">Verdict</div>
    <div class="verdict-value">{report.verdict}</div>
    <div class="stats-row" style="margin-top:12px">
      <div class="stat stat-crit"><span class="stat-num">{crit}</span><span class="stat-lab">CRITICAL</span></div>
      <div class="stat stat-high"><span class="stat-num">{high}</span><span class="stat-lab">HIGH</span></div>
      <div class="stat stat-med"><span class="stat-num">{med}</span><span class="stat-lab">MEDIUM</span></div>
      <div class="stat stat-low"><span class="stat-num">{low}</span><span class="stat-lab">LOW</span></div>
    </div>
  </div>
  <div class="score-ring" style="margin-left:auto">
    <div class="score-num">{report.score}</div>
    <div class="score-label">RISK SCORE / 100</div>
  </div>
</div>

<div class="main">

  <!-- FILE INFO -->
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <span class="section-icon">📄</span>
      <h2>File Information</h2>
      <span class="toggle-btn">▼</span>
    </div>
    <div class="section-body">
      <div class="info-grid">
        <div class="info-cell"><div class="info-label">Filename</div><div class="info-value">{report.filename}</div></div>
        <div class="info-cell"><div class="info-label">File Type</div><div class="info-value">{report.file_type}</div></div>
        <div class="info-cell"><div class="info-label">Size</div><div class="info-value">{report.file_size:,} bytes</div></div>
        <div class="info-cell"><div class="info-label">Entropy</div>
          <div class="info-value">{report.entropy:.4f}</div>
          <div class="entropy-bar-wrap"><div class="entropy-bar" style="width:{min(report.entropy/8*100,100):.1f}%"></div></div>
        </div>
        <div class="info-cell"><div class="info-label">MD5</div><div class="info-value">{report.md5}</div></div>
        <div class="info-cell"><div class="info-label">SHA1</div><div class="info-value">{report.sha1}</div></div>
        <div class="info-cell" style="grid-column:1/-1"><div class="info-label">SHA256</div><div class="info-value">{report.sha256}</div></div>
      </div>
    </div>
  </div>

  <!-- FINDINGS -->
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <span class="section-icon">🔍</span>
      <h2>Findings ({len(report.findings)})</h2>
      <span class="toggle-btn">▼</span>
    </div>
    <div class="section-body">
      <div class="filter-bar">
        <button class="filter-btn active" onclick="filterFindings('ALL',this)">ALL</button>
        <button class="filter-btn" onclick="filterFindings('CRITICAL',this)" style="border-color:#ff224455;color:#ff6688">CRITICAL</button>
        <button class="filter-btn" onclick="filterFindings('HIGH',this)" style="border-color:#ff660055;color:#ff9944">HIGH</button>
        <button class="filter-btn" onclick="filterFindings('MEDIUM',this)" style="border-color:#ffcc0055;color:#ffcc66">MEDIUM</button>
        <button class="filter-btn" onclick="filterFindings('LOW',this)" style="border-color:#33aaff55;color:#66aaff">LOW</button>
        <button class="filter-btn" onclick="filterFindings('EXPLOIT',this)" style="border-color:#ff44aa55;color:#ff88cc">EXPLOIT</button>
        <button class="filter-btn" onclick="filterFindings('MALWARE',this)" style="border-color:#aa44ff55;color:#cc88ff">MALWARE</button>
      </div>
      <div id="findings-container">
        {"".join([f'<div class="finding-card sev-{f.severity.lower()}" data-sev="{f.severity}" data-cat="{f.category}">' +
                  f'<div class="finding-header"><span class="finding-icon">{cat_icon.get(f.category,"•")}</span>' +
                  f'<span class="finding-title">{f.title}</span>' +
                  (f'<span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;{sev_badge.get(f.severity,"background:#333;color:#eee")}">{f.severity}</span>') +
                  f'<span class="cat-tag">{f.category}</span></div>' +
                  f'<div class="finding-body"><p>{f.description}</p>' +
                  (f'<code class="offset">Offset: 0x{f.offset:08X}</code>' if f.offset is not None else '') +
                  (f'<code class="data-hex">{f.data}</code>' if f.data else '') +
                  (f'<span class="yara-tag">YARA: {f.rule}</span>' if f.rule else '') +
                  '</div></div>' for f in report.findings] or ['<div class="empty-state">✓ No findings detected</div>'])}
      </div>
    </div>
  </div>

  <!-- YARA MATCHES -->
  {"" if not report.yara_matches else f'''
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <span class="section-icon">🎯</span>
      <h2>YARA Matches ({len(report.yara_matches)})</h2>
      <span class="toggle-btn">▼</span>
    </div>
    <div class="section-body">{yara_html or '<div class="empty-state">No YARA matches</div>'}</div>
  </div>'''}

  <!-- PE SECTIONS -->
  {"" if not report.sections else f'''
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <span class="section-icon">📦</span>
      <h2>PE Sections ({len(report.sections)})</h2>
      <span class="toggle-btn">▼</span>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Name</th><th>VAddr</th><th>VSize</th><th>Entropy</th></tr></thead>
      <tbody>{sections_html}</tbody></table>
    </div>
  </div>'''}

  <!-- IMPORTS -->
  {"" if not report.imports else f'''
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <span class="section-icon">📥</span>
      <h2>Imports ({len(report.imports)})</h2>
      <span class="toggle-btn">▼</span>
    </div>
    <div class="section-body" style="max-height:400px;overflow-y:auto">{imports_html}</div>
  </div>'''}

  <!-- DISASSEMBLY -->
  {"" if not report.disassembly else f'''
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <span class="section-icon">⚙️</span>
      <h2>Disassembly (first {len(report.disassembly)} instructions)</h2>
      <span class="toggle-btn">▼</span>
    </div>
    <div class="section-body" style="max-height:500px;overflow-y:auto">
      <table><thead><tr><th>Address</th><th>Bytes</th><th>Mnemonic</th><th>Operands</th></tr></thead>
      <tbody>{disasm_rows}</tbody></table>
    </div>
  </div>'''}

  <!-- STRINGS -->
  {"" if not report.strings_extracted else f'''
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <span class="section-icon">🔤</span>
      <h2>Extracted Strings ({len(report.strings_extracted)})</h2>
      <span class="toggle-btn">▼</span>
    </div>
    <div class="section-body" style="max-height:400px;overflow-y:auto">
      <table><thead><tr><th>Offset</th><th>Type</th><th>Value</th></tr></thead>
      <tbody>{strings_html}</tbody></table>
    </div>
  </div>'''}

</div>

<script>
function toggle(header) {{
  const body = header.nextElementSibling;
  const btn  = header.querySelector('.toggle-btn');
  if (body.style.display === 'none') {{
    body.style.display = '';
    btn.textContent = '▼';
  }} else {{
    body.style.display = 'none';
    btn.textContent = '▶';
  }}
}}

function filterFindings(filter, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#findings-container .finding-card').forEach(card => {{
    if (filter === 'ALL') {{
      card.style.display = '';
    }} else if (['EXPLOIT','MALWARE','SUSPICIOUS','INFO'].includes(filter)) {{
      card.style.display = card.dataset.cat === filter ? '' : 'none';
    }} else {{
      card.style.display = card.dataset.sev === filter ? '' : 'none';
    }}
  }});
}}
</script>
</body>
</html>"""
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)

# ── Main Orchestrator ─────────────────────────────────────────────────────────

def analyze_file(filepath: str, yara_rules: Optional[str] = None,
                 out_dir: str = ".", disasm: bool = True) -> AnalysisReport:
    path = Path(filepath)
    with open(filepath, 'rb') as f:
        data = f.read()

    hashes = compute_hashes(data)
    file_type = detect_file_type(data, filepath)
    entropy = compute_entropy(data)

    report = AnalysisReport(
        filename=path.name,
        file_size=len(data),
        file_type=file_type,
        md5=hashes['md5'],
        sha1=hashes['sha1'],
        sha256=hashes['sha256'],
        entropy=entropy,
        timestamp=datetime.datetime.now().isoformat(timespec='seconds'),
    )

    print(f"  [*] File: {path.name} ({file_type}, {len(data):,} bytes, entropy={entropy:.4f})")

    # String extraction
    print("  [*] Extracting strings...")
    report.strings_extracted = extract_strings(data)

    # Static analysis
    print("  [*] Running static analysis...")
    StaticAnalyzer().analyze(data, report)

    # Type-specific analysis
    if file_type == "PE":
        print("  [*] Analyzing PE structure...")
        PEAnalyzer().analyze(data, report)
    elif file_type == "ELF":
        print("  [*] Analyzing ELF structure...")
        ELFAnalyzer().analyze(data, report)
    elif file_type in ("JavaScript", "VBScript", "Text/Script"):
        print("  [*] Analyzing script...")
        ScriptAnalyzer().analyze(data, report)

    # YARA
    print("  [*] Running YARA rules...")
    YARAEngine().analyze(data, report, yara_rules)

    # Disassembly
    if disasm:
        print("  [*] Disassembling...")
        Disassembler().disassemble(data, file_type, report)

    # Score & verdict
    compute_verdict(report)

    # Write outputs
    os.makedirs(out_dir, exist_ok=True)
    stem = path.stem
    json_path = os.path.join(out_dir, f"{stem}_report.json")
    html_path = os.path.join(out_dir, f"{stem}_report.html")

    print("  [*] Writing JSON report...")
    write_json(report, json_path)
    print("  [*] Writing HTML report...")
    write_html(report, html_path)

    return report

def main():
    parser = argparse.ArgumentParser(
        description="Reverse Engineering & Malware Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 analyzer.py malware.exe
  python3 analyzer.py sample.bin --yara custom.yar --out ./reports
  python3 analyzer.py script.js --no-disasm
  python3 analyzer.py *.dll --out /tmp/analysis
        """
    )
    parser.add_argument('files', nargs='+', help='File(s) to analyze')
    parser.add_argument('--yara', '-y', metavar='FILE', help='Additional YARA rules file')
    parser.add_argument('--out',  '-o', metavar='DIR', default='./reports', help='Output directory (default: ./reports)')
    parser.add_argument('--no-disasm', action='store_true', help='Skip disassembly (faster)')
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════════════════════╗
║              Reverse Engineering & Malware Platform          ║
║  Static + Heuristic + YARA  |  PE · ELF · Shellcode · Script ║
╚══════════════════════════════════════════════════════════════╝
""")

    results = []
    for filepath in args.files:
        if not os.path.isfile(filepath):
            print(f"  [!] File not found: {filepath}")
            continue
        print(f"\n[+] Analyzing: {filepath}")
        try:
            report = analyze_file(
                filepath,
                yara_rules=args.yara,
                out_dir=args.out,
                disasm=not args.no_disasm
            )
            results.append(report)
            verdict_sym = {"MALWARE": "🦠", "SUSPICIOUS": "⚠️", "CLEAN": "✅"}.get(report.verdict, "?")
            print(f"\n  {verdict_sym} VERDICT: {report.verdict}  |  Risk Score: {report.score}/100")
            print(f"     Findings: {len(report.findings)} | YARA hits: {len(report.yara_matches)}")
            print(f"     Reports saved in: {args.out}/")
        except Exception as ex:
            print(f"  [!] Error analyzing {filepath}: {ex}")
            import traceback; traceback.print_exc()

    # Summary if multiple files
    if len(results) > 1:
        print(f"\n{'═'*60}")
        print(f"  BATCH SUMMARY — {len(results)} files analyzed")
        print(f"{'═'*60}")
        for r in results:
            sym = {"MALWARE": "🦠", "SUSPICIOUS": "⚠️", "CLEAN": "✅"}.get(r.verdict, "?")
            print(f"  {sym} [{r.score:3d}/100] {r.verdict:<10} {r.filename}")

if __name__ == '__main__':
    main()
