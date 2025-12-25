#!/usr/bin/env python3
"""
cortisol-dbgen: Generate the cortisol.db binary database from reference data.

Binary Format:
    Header (64 bytes)
    Payload Records (fixed size)
    Tamper Records (fixed size)
    WAF Signature Records (fixed size)
    String Table (variable, offset-referenced)
    Category Index
    WAF->Tamper Index
"""

import os
import re
import json
import struct
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum

# ============================================================================
# Constants
# ============================================================================

MAGIC = b"CORT"
VERSION = 1

# Fixed sizes for records (for O(1) access)
PAYLOAD_RECORD_SIZE = 72  # id(8) + cat(1) + zones(1) + blocked(1) + source(4) + hash(8) + len(2) + preview(40) + padding(7)
TAMPER_RECORD_SIZE = 48
WAF_RECORD_SIZE = 128

# Categories
class Category(IntEnum):
    UNKNOWN = 0
    SQLI = 1
    XSS = 2
    LFI = 3
    RFI = 4
    SSRF = 5
    SSTI = 6
    RCE = 7
    NOSQLI = 8
    LDAP = 9
    GRAPHQL = 10
    XXE = 11
    CSRF = 12
    OPEN_REDIRECT = 13
    PATH_TRAVERSAL = 14
    COMMAND_INJECTION = 15
    SSI = 16
    API = 17

class TamperCategory(IntEnum):
    ENCODING = 0
    CASE = 1
    SPACE = 2
    NULL = 3
    QUOTE = 4
    KEYWORD = 5
    WRAPPER = 6
    OBFUSCATION = 7
    UNICODE = 8

class Zone(IntEnum):
    URL = 1
    ARGS = 2
    BODY = 4
    COOKIE = 8
    HEADER = 16
    USER_AGENT = 32
    REFERER = 64

# Category mapping from folder names
CATEGORY_MAP = {
    "sqli": Category.SQLI,
    "sql": Category.SQLI,
    "sql injection": Category.SQLI,
    "xss": Category.XSS,
    "xss injection": Category.XSS,
    "lfi": Category.LFI,
    "file inclusion": Category.LFI,
    "rfi": Category.RFI,
    "ssrf": Category.SSRF,
    "server side request forgery": Category.SSRF,
    "ssti": Category.SSTI,
    "server side template injection": Category.SSTI,
    "rce": Category.RCE,
    "command injection": Category.COMMAND_INJECTION,
    "nosqli": Category.NOSQLI,
    "nosql injection": Category.NOSQLI,
    "ldap": Category.LDAP,
    "ldap injection": Category.LDAP,
    "graphql": Category.GRAPHQL,
    "graphql injection": Category.GRAPHQL,
    "xxe": Category.XXE,
    "xxe injection": Category.XXE,
    "or": Category.OPEN_REDIRECT,
    "open redirect": Category.OPEN_REDIRECT,
    "cm": Category.COMMAND_INJECTION,
    "ssi": Category.SSI,
    "api": Category.API,
    "uwa": Category.PATH_TRAVERSAL,
    "path traversal": Category.PATH_TRAVERSAL,
    "directory traversal": Category.PATH_TRAVERSAL,
}

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class Payload:
    id: int
    category: Category
    raw_payload: bytes
    zones: int  # bitmask of Zone
    blocked_expected: bool
    source_id: int  # string table offset
    
@dataclass
class Tamper:
    id: int
    name: str
    category: TamperCategory
    deterministic: bool
    
@dataclass  
class WafSignature:
    id: int
    name: str
    vendor: str
    header_patterns: list  # [(header_name, match_type, match_value), ...]
    body_patterns: list    # [regex_pattern, ...]
    status_codes: list     # [403, 503, ...]

# ============================================================================
# String Table
# ============================================================================

class StringTable:
    def __init__(self):
        self.strings = {}  # hash -> (offset, string)
        self.data = bytearray()
        self.current_offset = 0
        
    def add(self, s: str) -> int:
        """Add string to table, return offset. Deduplicates."""
        if not s:
            return 0xFFFFFFFF  # null marker
            
        h = hashlib.md5(s.encode()).hexdigest()
        if h in self.strings:
            return self.strings[h][0]
            
        offset = self.current_offset
        encoded = s.encode('utf-8')
        length = len(encoded)
        
        # Format: [u16 length][bytes]
        self.data.extend(struct.pack('<H', length))
        self.data.extend(encoded)
        
        self.current_offset += 2 + length
        self.strings[h] = (offset, s)
        
        return offset
        
    def get_bytes(self) -> bytes:
        return bytes(self.data)

# ============================================================================
# Parsers
# ============================================================================

def parse_waf_bypass_payloads(reference_dir: Path) -> list[Payload]:
    """Parse JSON payloads from waf-bypass/utils/payload/"""
    payloads = []
    payload_dir = reference_dir / "waf-bypass" / "utils" / "payload"
    
    if not payload_dir.exists():
        print(f"  Warning: {payload_dir} not found")
        return payloads
        
    payload_id = 0
    
    for category_dir in payload_dir.iterdir():
        if not category_dir.is_dir():
            continue
            
        category_name = category_dir.name.lower()
        category = CATEGORY_MAP.get(category_name, Category.UNKNOWN)
        
        for json_file in category_dir.glob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    
                for item in data.get("payload", []):
                    # Parse zones
                    zones = 0
                    if "URL" in item:
                        zones |= Zone.URL
                    if "ARGS" in item:
                        zones |= Zone.ARGS
                    if "BODY" in item:
                        zones |= Zone.BODY
                    if "COOKIE" in item:
                        zones |= Zone.COOKIE
                    if "HEADER" in item:
                        zones |= Zone.HEADER
                    if "USER-AGENT" in item:
                        zones |= Zone.USER_AGENT
                    if "REFERER" in item:
                        zones |= Zone.REFERER
                        
                    # Get the payload from first available zone
                    raw = None
                    for zone_key in ["URL", "ARGS", "BODY", "COOKIE", "HEADER", "USER-AGENT", "REFERER"]:
                        if zone_key in item and item[zone_key]:
                            raw = item[zone_key]
                            break
                            
                    if raw:
                        # Remove %RND% placeholders
                        raw = raw.replace("%RND%", "")
                        
                        payloads.append(Payload(
                            id=payload_id,
                            category=category,
                            raw_payload=raw.encode('utf-8', errors='replace'),
                            zones=zones,
                            blocked_expected=item.get("BLOCKED", True),
                            source_id=0  # will be set later
                        ))
                        payload_id += 1
                        
            except (json.JSONDecodeError, KeyError) as e:
                print(f"  Warning: Failed to parse {json_file}: {e}")
                
    return payloads

def parse_whatwaf_signatures(reference_dir: Path) -> list[WafSignature]:
    """Parse WAF detection plugins from WhatWaf/content/plugins/"""
    signatures = []
    plugins_dir = reference_dir / "WhatWaf" / "content" / "plugins"
    
    if not plugins_dir.exists():
        print(f"  Warning: {plugins_dir} not found")
        return signatures
        
    sig_id = 0
    
    for plugin_file in plugins_dir.glob("*.py"):
        if plugin_file.name == "__init__.py":
            continue
            
        try:
            content = plugin_file.read_text()
            
            # Extract product name
            product_match = re.search(r'__product__\s*=\s*["\']([^"\']+)["\']', content)
            if not product_match:
                continue
                
            product = product_match.group(1)
            
            # Extract vendor from product name (usually in parentheses)
            vendor = ""
            vendor_match = re.search(r'\(([^)]+)\)', product)
            if vendor_match:
                vendor = vendor_match.group(1)
                
            # Extract header patterns from detect function
            header_patterns = []
            header_matches = re.findall(r'headers\.get\(["\']([^"\']+)["\']', content, re.I)
            for h in header_matches:
                header_patterns.append((h.lower(), "exists", ""))
                
            # Extract regex patterns
            body_patterns = []
            regex_matches = re.findall(r're\.compile\(r["\']([^"\']+)["\']', content)
            for r in regex_matches[:5]:  # limit to 5 patterns per WAF
                body_patterns.append(r)
                
            signatures.append(WafSignature(
                id=sig_id,
                name=product.split('(')[0].strip(),
                vendor=vendor,
                header_patterns=header_patterns,
                body_patterns=body_patterns,
                status_codes=[403]  # default
            ))
            sig_id += 1
            
        except Exception as e:
            print(f"  Warning: Failed to parse {plugin_file}: {e}")
            
    return signatures

def parse_tampers(reference_dir: Path) -> list[Tamper]:
    """Parse tamper functions from WhatWaf and WAF-Bypass-Payloads"""
    tampers = []
    tamper_id = 0
    
    # Hardcoded list from our analysis of the Go file
    go_tampers = [
        ("apostrephemask", TamperCategory.QUOTE, True),
        ("apostrephenullify", TamperCategory.QUOTE, True),
        ("appendnull", TamperCategory.NULL, True),
        ("base64encode", TamperCategory.ENCODING, True),
        ("booleanmask", TamperCategory.KEYWORD, True),
        ("doubleurlencode", TamperCategory.ENCODING, True),
        ("enclosebrackets", TamperCategory.OBFUSCATION, False),
        ("escapequotes", TamperCategory.QUOTE, True),
        ("lowercase", TamperCategory.CASE, True),
        ("lowlevelunicodecharacter", TamperCategory.UNICODE, True),
        ("maskenclosebrackets", TamperCategory.OBFUSCATION, False),
        ("modsec", TamperCategory.WRAPPER, True),
        ("modsecspace2comment", TamperCategory.WRAPPER, True),
        ("obfuscatebyhtml", TamperCategory.ENCODING, True),
        ("obfuscatebyordinal", TamperCategory.ENCODING, True),
        ("prependnull", TamperCategory.NULL, True),
        ("randomcase", TamperCategory.CASE, False),
        ("randomcomments", TamperCategory.OBFUSCATION, False),
        ("randomtabify", TamperCategory.SPACE, False),
        ("randomunicode", TamperCategory.UNICODE, False),
        ("space2comment", TamperCategory.SPACE, True),
        ("space2doubledashes", TamperCategory.SPACE, True),
        ("space2hash", TamperCategory.SPACE, False),
        ("space2multicomment", TamperCategory.SPACE, False),
        ("space2null", TamperCategory.SPACE, True),
        ("space2plus", TamperCategory.SPACE, True),
        ("space2randomblank", TamperCategory.SPACE, False),
        ("space2slash", TamperCategory.SPACE, True),
        ("tabifyspacecommon", TamperCategory.SPACE, True),
        ("tabifyspaceuncommon", TamperCategory.SPACE, True),
        ("tripleurlencode", TamperCategory.ENCODING, True),
        ("uppercase", TamperCategory.CASE, True),
        ("urlencode", TamperCategory.ENCODING, True),
        ("urlencodeall", TamperCategory.ENCODING, True),
        ("htmlencodeall", TamperCategory.ENCODING, True),
        ("level1usingutf8", TamperCategory.UNICODE, True),
        ("level2usingutf8", TamperCategory.UNICODE, True),
        ("level3usingutf8", TamperCategory.UNICODE, True),
    ]
    
    for name, category, deterministic in go_tampers:
        tampers.append(Tamper(
            id=tamper_id,
            name=name,
            category=category,
            deterministic=deterministic
        ))
        tamper_id += 1
        
    # Also parse WhatWaf tampers
    tampers_dir = reference_dir / "WhatWaf" / "content" / "tampers"
    if tampers_dir.exists():
        for tamper_file in tampers_dir.glob("*.py"):
            if tamper_file.name == "__init__.py":
                continue
                
            name = tamper_file.stem
            # Skip if we already have it
            if any(t.name == name for t in tampers):
                continue
                
            try:
                content = tamper_file.read_text()
                
                # Check if it uses random
                deterministic = "random" not in content.lower()
                
                # Infer category from name
                category = TamperCategory.OBFUSCATION
                if "space" in name:
                    category = TamperCategory.SPACE
                elif "case" in name or "upper" in name or "lower" in name:
                    category = TamperCategory.CASE
                elif "encode" in name:
                    category = TamperCategory.ENCODING
                elif "null" in name:
                    category = TamperCategory.NULL
                elif "quote" in name or "apostrophe" in name:
                    category = TamperCategory.QUOTE
                    
                tampers.append(Tamper(
                    id=tamper_id,
                    name=name,
                    category=category,
                    deterministic=deterministic
                ))
                tamper_id += 1
                
            except Exception as e:
                print(f"  Warning: Failed to parse tamper {tamper_file}: {e}")
                
    return tampers

# ============================================================================
# Binary Writer
# ============================================================================

def write_database(output_path: Path, payloads: list[Payload], 
                   tampers: list[Tamper], waf_sigs: list[WafSignature]):
    """Write the binary database file."""
    
    string_table = StringTable()
    
    # Pre-populate string table with sources
    source_ids = {}
    for p in payloads:
        source = f"waf-bypass/{p.category.name}"
        if source not in source_ids:
            source_ids[source] = string_table.add(source)
        p.source_id = source_ids[source]
        
    # Add WAF names and patterns to string table
    waf_name_ids = {}
    for w in waf_sigs:
        waf_name_ids[w.id] = string_table.add(w.name)
        
    # Calculate offsets
    header_size = 64
    payload_table_size = len(payloads) * PAYLOAD_RECORD_SIZE
    tamper_table_size = len(tampers) * TAMPER_RECORD_SIZE
    waf_table_size = len(waf_sigs) * WAF_RECORD_SIZE
    
    payload_offset = header_size
    tamper_offset = payload_offset + payload_table_size
    waf_offset = tamper_offset + tamper_table_size
    string_table_offset = waf_offset + waf_table_size
    
    with open(output_path, 'wb') as f:
        # ========== HEADER (64 bytes) ==========
        header = bytearray(64)
        struct.pack_into('<4s', header, 0, MAGIC)           # magic
        struct.pack_into('<H', header, 4, VERSION)          # version
        struct.pack_into('<I', header, 6, len(payloads))    # payload_count
        struct.pack_into('<H', header, 10, len(tampers))    # tamper_count
        struct.pack_into('<H', header, 12, len(waf_sigs))   # waf_count
        struct.pack_into('<Q', header, 16, payload_offset)  # payload_offset
        struct.pack_into('<Q', header, 24, tamper_offset)   # tamper_offset
        struct.pack_into('<Q', header, 32, waf_offset)      # waf_offset
        struct.pack_into('<Q', header, 40, string_table_offset)  # string_table_offset
        f.write(header)
        
        # ========== PAYLOAD TABLE ==========
        for p in payloads:
            record = bytearray(PAYLOAD_RECORD_SIZE)
            struct.pack_into('<Q', record, 0, p.id)              # id
            struct.pack_into('<B', record, 8, p.category)        # category
            struct.pack_into('<B', record, 9, p.zones)           # zones bitmask
            struct.pack_into('<B', record, 10, 1 if p.blocked_expected else 0)  # blocked
            struct.pack_into('<I', record, 11, p.source_id)      # source string offset
            
            # Payload hash (for dedup/lookup)
            payload_hash = hashlib.md5(p.raw_payload).digest()[:8]
            record[15:23] = payload_hash
            
            # Payload length and truncated payload (for quick preview)
            struct.pack_into('<H', record, 23, len(p.raw_payload))
            preview = p.raw_payload[:40]
            record[25:25+len(preview)] = preview
            
            f.write(record)
            
        # ========== TAMPER TABLE ==========
        for t in tampers:
            record = bytearray(TAMPER_RECORD_SIZE)
            struct.pack_into('<H', record, 0, t.id)              # id
            struct.pack_into('<B', record, 2, t.category)        # category
            struct.pack_into('<B', record, 3, 1 if t.deterministic else 0)  # deterministic
            
            # Name (fixed 32 bytes, null-padded)
            name_bytes = t.name.encode('utf-8')[:32]
            record[4:4+len(name_bytes)] = name_bytes
            
            f.write(record)
            
        # ========== WAF SIGNATURE TABLE ==========
        for w in waf_sigs:
            record = bytearray(WAF_RECORD_SIZE)
            struct.pack_into('<H', record, 0, w.id)              # id
            struct.pack_into('<I', record, 2, waf_name_ids[w.id])  # name string offset
            
            # Name preview (fixed 48 bytes)
            name_bytes = w.name.encode('utf-8')[:48]
            record[6:6+len(name_bytes)] = name_bytes
            
            # Header pattern count
            struct.pack_into('<B', record, 54, min(len(w.header_patterns), 8))
            
            # Body pattern count  
            struct.pack_into('<B', record, 55, min(len(w.body_patterns), 5))
            
            # Status codes (up to 4)
            for i, code in enumerate(w.status_codes[:4]):
                struct.pack_into('<H', record, 56 + i*2, code)
                
            f.write(record)
            
        # ========== STRING TABLE ==========
        f.write(string_table.get_bytes())
        
        total_size = f.tell()
        
    return {
        'header_size': header_size,
        'payload_table_size': payload_table_size,
        'tamper_table_size': tamper_table_size,
        'waf_table_size': waf_table_size,
        'string_table_size': len(string_table.get_bytes()),
        'total_size': total_size
    }

# ============================================================================
# Payload Table (separate file for full payloads)
# ============================================================================

def write_payload_data(output_path: Path, payloads: list[Payload]):
    """Write full payload data to a separate file (referenced by hash)."""
    
    with open(output_path, 'wb') as f:
        # Header
        f.write(struct.pack('<4s', b"CPAY"))  # magic
        f.write(struct.pack('<I', len(payloads)))  # count
        
        # Offset table (for direct access by ID)
        offset_table_start = 8
        data_start = offset_table_start + len(payloads) * 8
        
        offsets = []
        current_offset = data_start
        
        for p in payloads:
            offsets.append(current_offset)
            current_offset += 4 + len(p.raw_payload)  # length prefix + data
            
        # Write offset table
        for offset in offsets:
            f.write(struct.pack('<Q', offset))
            
        # Write payload data
        for p in payloads:
            f.write(struct.pack('<I', len(p.raw_payload)))
            f.write(p.raw_payload)

# ============================================================================
# Main
# ============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate cortisol.db from reference data')
    parser.add_argument('--reference-dir', '-r', type=Path, 
                        default=Path(__file__).parent.parent / 'reference_data',
                        help='Path to reference_data directory')
    parser.add_argument('--output', '-o', type=Path,
                        default=Path(__file__).parent.parent / 'cortisol.db',
                        help='Output database file')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
                        
    args = parser.parse_args()
    
    print(f"╔═══════════════════════════════════════════════════════════╗")
    print(f"║          cortisol-dbgen: Database Generator               ║")
    print(f"╚═══════════════════════════════════════════════════════════╝")
    print()
    
    print(f"[*] Reference directory: {args.reference_dir}")
    print(f"[*] Output file: {args.output}")
    print()
    
    # Parse all data sources
    print("[1/4] Parsing payloads from waf-bypass...")
    payloads = parse_waf_bypass_payloads(args.reference_dir)
    print(f"      Found {len(payloads)} payloads")
    
    print("[2/4] Parsing WAF signatures from WhatWaf...")
    waf_sigs = parse_whatwaf_signatures(args.reference_dir)
    print(f"      Found {len(waf_sigs)} WAF signatures")
    
    print("[3/4] Parsing tamper functions...")
    tampers = parse_tampers(args.reference_dir)
    print(f"      Found {len(tampers)} tamper functions")
    
    print("[4/4] Writing database...")
    stats = write_database(args.output, payloads, tampers, waf_sigs)
    
    # Write full payload data
    payload_data_path = args.output.with_suffix('.payloads')
    write_payload_data(payload_data_path, payloads)
    
    print()
    print(f"╔═══════════════════════════════════════════════════════════╗")
    print(f"║                    Generation Complete                    ║")
    print(f"╠═══════════════════════════════════════════════════════════╣")
    print(f"║  Payloads:     {len(payloads):>6}                                   ║")
    print(f"║  Tampers:      {len(tampers):>6}                                   ║")
    print(f"║  WAF Sigs:     {len(waf_sigs):>6}                                   ║")
    print(f"╠═══════════════════════════════════════════════════════════╣")
    
    db_size = args.output.stat().st_size
    payload_size = payload_data_path.stat().st_size
    print(f"║  cortisol.db:      {db_size:>10} bytes                    ║")
    print(f"║  cortisol.payloads:{payload_size:>10} bytes                    ║")
    print(f"║  Total:            {db_size + payload_size:>10} bytes                    ║")
    print(f"╚═══════════════════════════════════════════════════════════╝")
    
    # Category breakdown
    if args.verbose:
        print("\nPayload breakdown by category:")
        from collections import Counter
        cats = Counter(p.category.name for p in payloads)
        for cat, count in cats.most_common():
            print(f"  {cat}: {count}")

if __name__ == '__main__':
    main()
