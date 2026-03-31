import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .patterns import (
    BIDI_CHARACTERS,
    ZERO_WIDTH_CHARACTERS,
    COMMON_HOMOGLYPHS,
    DEFAULT_EXTENSIONS,
    is_tag_character,
    is_pua_character,
    RISK_LEVELS,
)

@dataclass
class Finding:
    file_path: str  
    line_number: int   
    column: int         
    char: str
    char_unicode: str
    char_name: str     
    category: str    
    risk_level: str     
    line_preview: str    
    context_safe: str    


@dataclass
class ScanResult:
    files_scanned: int = 0
    files_with_findings: int = 0
    total_findings: int = 0
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _check_if_context_safe(file_path: str, category: str) -> str:
    ext = Path(file_path).suffix.lower()
    filename = Path(file_path).name.lower()
    if ext in (".md", ".txt", ".rst") and category == "bidi":
        return "Possible legitimate RTL text, verify manually"
    if category == "zero_width":
        return "Possible encoded payload, inspect surrounding bytes"
    return "No legitimate use expected in source code"


def scan_content(content: str, file_path: str) -> list:
    findings = []
    lines = content.split("\n")
    for line_num, line in enumerate(lines, start=1):
        for col, char in enumerate(line, start=1):
            if char in BIDI_CHARACTERS:
                findings.append(Finding(
                    file_path=file_path,
                    line_number=line_num,
                    column=col,
                    char=char,
                    char_unicode=f"U+{ord(char):04X}",
                    char_name=BIDI_CHARACTERS[char],
                    category="bidi",
                    risk_level=RISK_LEVELS["bidi"],
                    line_preview=line.strip()[:120],
                    context_safe=_check_if_context_safe(file_path, "bidi"),
                ))

            elif char in ZERO_WIDTH_CHARACTERS:
                findings.append(Finding(
                    file_path=file_path,
                    line_number=line_num,
                    column=col,
                    char=char,
                    char_unicode=f"U+{ord(char):04X}",
                    char_name=ZERO_WIDTH_CHARACTERS[char],
                    category="zero_width",
                    risk_level=RISK_LEVELS["zero_width"],
                    line_preview=line.strip()[:120],
                    context_safe=_check_if_context_safe(file_path, "zero_width"),
                ))

            elif is_tag_character(char):
                findings.append(Finding(
                    file_path=file_path,
                    line_number=line_num,
                    column=col,
                    char=char,
                    char_unicode=f"U+{ord(char):04X}",
                    char_name=f"Unicode Tag Character (U+{ord(char):04X})",
                    category="tag",
                    risk_level=RISK_LEVELS["tag"],
                    line_preview=line.strip()[:120],
                    context_safe="No legitimate use in source code, likely AI prompt injection",
                ))

            elif char in COMMON_HOMOGLYPHS:
                findings.append(Finding(
                    file_path=file_path,
                    line_number=line_num,
                    column=col,
                    char=char,
                    char_unicode=f"U+{ord(char):04X}",
                    char_name=COMMON_HOMOGLYPHS[char],
                    category="homoglyph",
                    risk_level=RISK_LEVELS["homoglyph"],
                    line_preview=line.strip()[:120],
                    context_safe="May be legitimate in string literals, verify",
                ))

            elif is_pua_character(char):
                findings.append(Finding(
                    file_path=file_path,
                    line_number=line_num,
                    column=col,
                    char=char,
                    char_unicode=f"U+{ord(char):04X}",
                    char_name="Private Use Area Character",
                    category="pua",
                    risk_level=RISK_LEVELS["pua"],
                    line_preview=line.strip()[:120],
                    context_safe=_check_if_context_safe(file_path, "pua"),
                ))

    return findings


def scan_file(file_path: str) -> tuple[list, Optional[str]]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return scan_content(content, file_path), None
    except PermissionError:
        return [], f"Permission denied: {file_path}"
    except Exception as e:
        return [], f"Could not read {file_path}: {str(e)}"


def scan_directory(
    directory: str,
    extensions: Optional[set] = None,
    recursive: bool = True,
    skip_dirs: Optional[set] = None,
) -> ScanResult:
    if extensions is None:
        extensions = DEFAULT_EXTENSIONS

    if skip_dirs is None:
        skip_dirs = {
            "node_modules", ".git", "venv", ".venv", "__pycache__",
            "dist", "build", ".next", "vendor", "target", "out",
            ".tox", "coverage", ".pytest_cache", ".mypy_cache"
        }

    result = ScanResult()
    root = Path(directory)

    if not root.exists():
        result.errors.append(f"Directory does not exist: {directory}")
        return result

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        if not recursive and dirpath != str(root):
            break
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            ext = Path(filename).suffix.lower()
            if ext not in extensions:
                continue

            result.files_scanned += 1
            findings, error = scan_file(file_path)

            if error:
                result.errors.append(error)
            elif findings:
                result.files_with_findings += 1
                result.total_findings += len(findings)
                result.findings.extend(findings)

    return result