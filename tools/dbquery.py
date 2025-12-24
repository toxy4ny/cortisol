#!/usr/bin/env python3
"""
cortisol-dbquery: Query and verify the cortisol.db database.

Usage:
    python tools/dbquery.py --stats           # Show database statistics
    python tools/dbquery.py --payloads sqli   # List SQLi payloads
    python tools/dbquery.py --tampers         # List all tampers
    python tools/dbquery.py --wafs            # List all WAF signatures
    python tools/dbquery.py --payload-id 42   # Get specific payload
    python tools/dbquery.py --verify          # Verify database integrity
"""

import os
import struct
import mmap
from pathlib import Path
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Iterator

# ============================================================================
# Constants (must match dbgen.py)
# ============================================================================

MAGIC = b"CORT"
VERSION = 1

PAYLOAD_RECORD_SIZE = 72
TAMPER_RECORD_SIZE = 48
WAF_RECORD_SIZE = 128

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

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class Header:
    magic: bytes
    version: int
    payload_count: int
    tamper_count: int
    waf_count: int
    payload_offset: int
    tamper_offset: int
    waf_offset: int
    string_table_offset: int

@dataclass
class PayloadRecord:
    id: int
    category: Category
    zones: int
    blocked_expected: bool
    source_id: int
    payload_hash: bytes
    payload_len: int
    preview: bytes

@dataclass
class TamperRecord:
    id: int
    category: TamperCategory
    deterministic: bool
    name: str

@dataclass
class WafRecord:
    id: int
    name_offset: int
    name: str
    header_pattern_count: int
    body_pattern_count: int
    status_codes: list[int]

# ============================================================================
# Database Reader (mmap-based)
# ============================================================================

class CortisolDB:
    def __init__(self, db_path: Path, payloads_path: Optional[Path] = None):
        self.db_path = db_path
        self.payloads_path = payloads_path or db_path.with_suffix('.payloads')
        
        # Memory-map the main database
        self.db_file = open(db_path, 'rb')
        self.db_mmap = mmap.mmap(self.db_file.fileno(), 0, access=mmap.ACCESS_READ)
        
        # Memory-map the payloads file if it exists
        self.payloads_mmap = None
        if self.payloads_path.exists():
            self.payloads_file = open(self.payloads_path, 'rb')
            self.payloads_mmap = mmap.mmap(self.payloads_file.fileno(), 0, access=mmap.ACCESS_READ)
        
        # Parse header
        self.header = self._read_header()
        
    def _read_header(self) -> Header:
        data = self.db_mmap[0:64]
        magic = data[0:4]
        version, = struct.unpack_from('<H', data, 4)
        payload_count, = struct.unpack_from('<I', data, 6)
        tamper_count, = struct.unpack_from('<H', data, 10)
        waf_count, = struct.unpack_from('<H', data, 12)
        payload_offset, = struct.unpack_from('<Q', data, 16)
        tamper_offset, = struct.unpack_from('<Q', data, 24)
        waf_offset, = struct.unpack_from('<Q', data, 32)
        string_table_offset, = struct.unpack_from('<Q', data, 40)
        
        return Header(
            magic=magic,
            version=version,
            payload_count=payload_count,
            tamper_count=tamper_count,
            waf_count=waf_count,
            payload_offset=payload_offset,
            tamper_offset=tamper_offset,
            waf_offset=waf_offset,
            string_table_offset=string_table_offset
        )
        
    def get_payload(self, payload_id: int) -> Optional[PayloadRecord]:
        if payload_id < 0 or payload_id >= self.header.payload_count:
            return None
            
        offset = self.header.payload_offset + payload_id * PAYLOAD_RECORD_SIZE
        data = self.db_mmap[offset:offset + PAYLOAD_RECORD_SIZE]
        
        id_, = struct.unpack_from('<Q', data, 0)
        category = Category(data[8])
        zones = data[9]
        blocked = bool(data[10])
        source_id, = struct.unpack_from('<I', data, 11)
        payload_hash = data[15:23]
        payload_len, = struct.unpack_from('<H', data, 23)
        preview = data[25:65].rstrip(b'\x00')
        
        return PayloadRecord(
            id=id_,
            category=category,
            zones=zones,
            blocked_expected=blocked,
            source_id=source_id,
            payload_hash=payload_hash,
            payload_len=payload_len,
            preview=preview
        )
        
    def get_full_payload(self, payload_id: int) -> Optional[bytes]:
        """Get full payload data from the payloads file."""
        if not self.payloads_mmap:
            return None
            
        if payload_id < 0 or payload_id >= self.header.payload_count:
            return None
            
        # Read offset from offset table
        offset_table_start = 8
        offset_pos = offset_table_start + payload_id * 8
        offset, = struct.unpack_from('<Q', self.payloads_mmap, offset_pos)
        
        # Read length and data
        length, = struct.unpack_from('<I', self.payloads_mmap, offset)
        data = self.payloads_mmap[offset + 4:offset + 4 + length]
        
        return bytes(data)
        
    def iter_payloads(self, category: Optional[Category] = None) -> Iterator[PayloadRecord]:
        for i in range(self.header.payload_count):
            record = self.get_payload(i)
            if record and (category is None or record.category == category):
                yield record
                
    def get_tamper(self, tamper_id: int) -> Optional[TamperRecord]:
        if tamper_id < 0 or tamper_id >= self.header.tamper_count:
            return None
            
        offset = self.header.tamper_offset + tamper_id * TAMPER_RECORD_SIZE
        data = self.db_mmap[offset:offset + TAMPER_RECORD_SIZE]
        
        id_, = struct.unpack_from('<H', data, 0)
        category = TamperCategory(data[2])
        deterministic = bool(data[3])
        name = data[4:36].rstrip(b'\x00').decode('utf-8')
        
        return TamperRecord(
            id=id_,
            category=category,
            deterministic=deterministic,
            name=name
        )
        
    def iter_tampers(self) -> Iterator[TamperRecord]:
        for i in range(self.header.tamper_count):
            record = self.get_tamper(i)
            if record:
                yield record
                
    def get_waf(self, waf_id: int) -> Optional[WafRecord]:
        if waf_id < 0 or waf_id >= self.header.waf_count:
            return None
            
        offset = self.header.waf_offset + waf_id * WAF_RECORD_SIZE
        data = self.db_mmap[offset:offset + WAF_RECORD_SIZE]
        
        id_, = struct.unpack_from('<H', data, 0)
        name_offset, = struct.unpack_from('<I', data, 2)
        name = data[6:54].rstrip(b'\x00').decode('utf-8')
        header_count = data[54]
        body_count = data[55]
        
        status_codes = []
        for i in range(4):
            code, = struct.unpack_from('<H', data, 56 + i*2)
            if code > 0:
                status_codes.append(code)
        
        return WafRecord(
            id=id_,
            name_offset=name_offset,
            name=name,
            header_pattern_count=header_count,
            body_pattern_count=body_count,
            status_codes=status_codes
        )
        
    def iter_wafs(self) -> Iterator[WafRecord]:
        for i in range(self.header.waf_count):
            record = self.get_waf(i)
            if record:
                yield record
                
    def get_string(self, offset: int) -> Optional[str]:
        if offset == 0xFFFFFFFF:
            return None
            
        pos = self.header.string_table_offset + offset
        length, = struct.unpack_from('<H', self.db_mmap, pos)
        data = self.db_mmap[pos + 2:pos + 2 + length]
        return data.decode('utf-8')
        
    def verify(self) -> tuple[bool, list[str]]:
        """Verify database integrity."""
        errors = []
        
        # Check magic
        if self.header.magic != MAGIC:
            errors.append(f"Invalid magic: {self.header.magic}")
            
        # Check version
        if self.header.version != VERSION:
            errors.append(f"Version mismatch: {self.header.version} != {VERSION}")
            
        # Verify payload records
        for i in range(min(10, self.header.payload_count)):
            p = self.get_payload(i)
            if p is None:
                errors.append(f"Failed to read payload {i}")
            elif p.id != i:
                errors.append(f"Payload ID mismatch: {p.id} != {i}")
                
        # Verify tamper records
        for i in range(self.header.tamper_count):
            t = self.get_tamper(i)
            if t is None:
                errors.append(f"Failed to read tamper {i}")
            elif not t.name:
                errors.append(f"Tamper {i} has empty name")
                
        # Verify WAF records
        for i in range(self.header.waf_count):
            w = self.get_waf(i)
            if w is None:
                errors.append(f"Failed to read WAF {i}")
            elif not w.name:
                errors.append(f"WAF {i} has empty name")
                
        # Verify payloads file
        if self.payloads_mmap:
            magic = self.payloads_mmap[0:4]
            if magic != b"CPAY":
                errors.append(f"Invalid payloads file magic: {magic}")
                
            count, = struct.unpack_from('<I', self.payloads_mmap, 4)
            if count != self.header.payload_count:
                errors.append(f"Payload count mismatch: {count} != {self.header.payload_count}")
                
        return len(errors) == 0, errors
        
    def close(self):
        self.db_mmap.close()
        self.db_file.close()
        if self.payloads_mmap:
            self.payloads_mmap.close()
            self.payloads_file.close()

# ============================================================================
# CLI
# ============================================================================

def zones_to_str(zones: int) -> str:
    names = []
    if zones & Zone.URL: names.append("URL")
    if zones & Zone.ARGS: names.append("ARGS")
    if zones & Zone.BODY: names.append("BODY")
    if zones & Zone.COOKIE: names.append("COOKIE")
    if zones & Zone.HEADER: names.append("HEADER")
    if zones & Zone.USER_AGENT: names.append("UA")
    if zones & Zone.REFERER: names.append("REF")
    return ",".join(names) if names else "-"

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Query cortisol.db database')
    parser.add_argument('--db', type=Path, 
                        default=Path(__file__).parent.parent / 'cortisol.db',
                        help='Path to cortisol.db')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    parser.add_argument('--verify', action='store_true', help='Verify database integrity')
    parser.add_argument('--payloads', type=str, metavar='CATEGORY', 
                        help='List payloads (optionally filter by category)')
    parser.add_argument('--tampers', action='store_true', help='List all tampers')
    parser.add_argument('--wafs', action='store_true', help='List all WAF signatures')
    parser.add_argument('--payload-id', type=int, help='Get specific payload by ID')
    parser.add_argument('--limit', type=int, default=20, help='Limit results')
    
    args = parser.parse_args()
    
    if not args.db.exists():
        print(f"Error: Database not found: {args.db}")
        print("Run: python tools/dbgen.py")
        return 1
        
    db = CortisolDB(args.db)
    
    try:
        if args.verify:
            print("Verifying database integrity...")
            ok, errors = db.verify()
            if ok:
                print("✅ Database integrity OK")
                print(f"   Payloads: {db.header.payload_count}")
                print(f"   Tampers:  {db.header.tamper_count}")
                print(f"   WAFs:     {db.header.waf_count}")
            else:
                print("❌ Database integrity FAILED")
                for e in errors:
                    print(f"   - {e}")
                return 1
                
        elif args.stats:
            print("╔═══════════════════════════════════════════════════════════╗")
            print("║              cortisol.db Statistics                       ║")
            print("╠═══════════════════════════════════════════════════════════╣")
            print(f"║  Magic:      {db.header.magic.decode()}                                        ║")
            print(f"║  Version:    {db.header.version}                                          ║")
            print(f"║  Payloads:   {db.header.payload_count:>6}                                   ║")
            print(f"║  Tampers:    {db.header.tamper_count:>6}                                   ║")
            print(f"║  WAF Sigs:   {db.header.waf_count:>6}                                   ║")
            print("╠═══════════════════════════════════════════════════════════╣")
            
            # Category breakdown
            from collections import Counter
            cats = Counter(p.category.name for p in db.iter_payloads())
            print("║  Payload Categories:                                      ║")
            for cat, count in cats.most_common(10):
                print(f"║    {cat:<20} {count:>5}                            ║")
            print("╚═══════════════════════════════════════════════════════════╝")
            
        elif args.payloads is not None:
            category = None
            if args.payloads:
                try:
                    category = Category[args.payloads.upper()]
                except KeyError:
                    print(f"Unknown category: {args.payloads}")
                    print(f"Valid categories: {', '.join(c.name for c in Category)}")
                    return 1
                    
            print(f"{'ID':>5} {'Category':<15} {'Zones':<12} {'Len':>5} {'Preview':<40}")
            print("-" * 80)
            
            for i, p in enumerate(db.iter_payloads(category)):
                if i >= args.limit:
                    print(f"... ({db.header.payload_count - args.limit} more)")
                    break
                preview = p.preview.decode('utf-8', errors='replace')[:40]
                print(f"{p.id:>5} {p.category.name:<15} {zones_to_str(p.zones):<12} {p.payload_len:>5} {preview:<40}")
                
        elif args.tampers:
            print(f"{'ID':>3} {'Category':<12} {'Det':>3} {'Name':<32}")
            print("-" * 55)
            
            for t in db.iter_tampers():
                det = "✓" if t.deterministic else "✗"
                print(f"{t.id:>3} {t.category.name:<12} {det:>3} {t.name:<32}")
                
        elif args.wafs:
            print(f"{'ID':>3} {'Name':<40} {'Headers':>7} {'Body':>5} {'Codes':<12}")
            print("-" * 75)
            
            for w in db.iter_wafs():
                codes = ",".join(str(c) for c in w.status_codes)
                print(f"{w.id:>3} {w.name:<40} {w.header_pattern_count:>7} {w.body_pattern_count:>5} {codes:<12}")
                
        elif args.payload_id is not None:
            p = db.get_payload(args.payload_id)
            if p:
                print(f"Payload #{p.id}")
                print(f"  Category: {p.category.name}")
                print(f"  Zones:    {zones_to_str(p.zones)}")
                print(f"  Blocked:  {p.blocked_expected}")
                print(f"  Length:   {p.payload_len}")
                print(f"  Hash:     {p.payload_hash.hex()}")
                print(f"  Source:   {db.get_string(p.source_id)}")
                print(f"  Preview:  {p.preview.decode('utf-8', errors='replace')}")
                
                full = db.get_full_payload(args.payload_id)
                if full:
                    print(f"  Full:     {full.decode('utf-8', errors='replace')}")
            else:
                print(f"Payload {args.payload_id} not found")
                return 1
                
        else:
            parser.print_help()
            
    finally:
        db.close()
        
    return 0

if __name__ == '__main__':
    exit(main())
