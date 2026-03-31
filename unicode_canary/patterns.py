# CVE-2021-42574

BIDI_CHARACTERS = {
    "\u202A": "Left-to-Right Embedding (LRE)",
    "\u202B": "Right-to-Left Embedding (RLE)",
    "\u202C": "Pop Directional Formatting (PDF)",
    "\u202D": "Left-to-Right Override (LRO)",
    "\u202E": "Right-to-Left Override (RLO)",  
    "\u2066": "Left-to-Right Isolate (LRI)",
    "\u2067": "Right-to-Left Isolate (RLI)",
    "\u2068": "First Strong Isolate (FSI)",
    "\u2069": "Pop Directional Isolate (PDI)",
    "\u200F": "Right-to-Left Mark (RLM)",
    "\u200E": "Left-to-Right Mark (LRM)",
}

ZERO_WIDTH_CHARACTERS = {
    "\u200B": "Zero-Width Space (ZWSP)",
    "\u200C": "Zero-Width Non-Joiner (ZWNJ)",
    "\u200D": "Zero-Width Joiner (ZWJ)",
    "\u2060": "Word Joiner",
    "\uFEFF": "Zero-Width No-Break Space / BOM",
    "\u00AD": "Soft Hyphen",
    "\u034F": "Combining Grapheme Joiner",
    "\u180E": "Mongolian Vowel Separator",
}

TAG_CHARACTER_RANGE = (0xE0000, 0xE007F)  

def is_tag_character(char: str) -> bool:
    return TAG_CHARACTER_RANGE[0] <= ord(char) <= TAG_CHARACTER_RANGE[1]

COMMON_HOMOGLYPHS = {
    "\u0430": "Cyrillic 'а' (looks like Latin 'a')",
    "\u0435": "Cyrillic 'е' (looks like Latin 'e')",
    "\u043E": "Cyrillic 'о' (looks like Latin 'o')",
    "\u0440": "Cyrillic 'р' (looks like Latin 'p')",
    "\u0441": "Cyrillic 'с' (looks like Latin 'c')",
    "\u0445": "Cyrillic 'х' (looks like Latin 'x')",
    "\u0456": "Cyrillic 'і' (looks like Latin 'i')",
    "\u03BF": "Greek 'ο' (looks like Latin 'o')",
    "\u03B1": "Greek 'α' (looks like Latin 'a')",
    "\u2010": "Hyphen (not a dash, not ASCII hyphen)",
    "\u2011": "Non-Breaking Hyphen",
}

PUA_RANGES = [
    (0xE000, 0xF8FF),    
    (0xF0000, 0xFFFFF),  
    (0x100000, 0x10FFFF) 
]

def is_pua_character(char: str) -> bool:
    cp = ord(char)
    return any(start <= cp <= end for start, end in PUA_RANGES)

DEFAULT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rs", ".c", ".cpp",
    ".h", ".hpp", ".cs", ".php", ".rb",
    ".sh", ".bash", ".zsh", ".yaml", ".yml",
    ".json", ".toml", ".env", ".md", ".txt"
}

RISK_LEVELS = {
    "bidi": "CRITICAL",
    "zero_width": "HIGH",
    "tag": "HIGH",
    "homoglyph": "MEDIUM",
    "pua": "HIGH",
}