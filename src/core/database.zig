const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const os = std.os;

pub const MAGIC = "CORT";
pub const VERSION: u16 = 1;

pub const PAYLOAD_RECORD_SIZE: usize = 72;
pub const TAMPER_RECORD_SIZE: usize = 48;
pub const WAF_RECORD_SIZE: usize = 128;

pub const Category = enum(u8) {
    unknown = 0,
    sqli = 1,
    xss = 2,
    lfi = 3,
    rfi = 4,
    ssrf = 5,
    ssti = 6,
    rce = 7,
    nosqli = 8,
    ldap = 9,
    graphql = 10,
    xxe = 11,
    csrf = 12,
    open_redirect = 13,
    path_traversal = 14,
    command_injection = 15,
    ssi = 16,
    api = 17,
    _,

    pub fn toString(self: Category) []const u8 {
        return switch (self) {
            .unknown => "UNKNOWN",
            .sqli => "SQLi",
            .xss => "XSS",
            .lfi => "LFI",
            .rfi => "RFI",
            .ssrf => "SSRF",
            .ssti => "SSTI",
            .rce => "RCE",
            .nosqli => "NoSQLi",
            .ldap => "LDAP",
            .graphql => "GraphQL",
            .xxe => "XXE",
            .csrf => "CSRF",
            .open_redirect => "Open Redirect",
            .path_traversal => "Path Traversal",
            .command_injection => "Command Injection",
            .ssi => "SSI",
            .api => "API",
            _ => "OTHER",
        };
    }
};

pub const TamperCategory = enum(u8) {
    encoding = 0,
    case = 1,
    space = 2,
    null_byte = 3,
    quote = 4,
    keyword = 5,
    wrapper = 6,
    obfuscation = 7,
    unicode = 8,
    _,

    pub fn toString(self: TamperCategory) []const u8 {
        return switch (self) {
            .encoding => "ENCODING",
            .case => "CASE",
            .space => "SPACE",
            .null_byte => "NULL",
            .quote => "QUOTE",
            .keyword => "KEYWORD",
            .wrapper => "WRAPPER",
            .obfuscation => "OBFUSCATION",
            .unicode => "UNICODE",
            _ => "OTHER",
        };
    }
};

pub const Zone = packed struct {
    url: bool = false,
    args: bool = false,
    body: bool = false,
    cookie: bool = false,
    header: bool = false,
    user_agent: bool = false,
    referer: bool = false,
    _padding: u1 = 0,

    pub fn fromByte(byte: u8) Zone {
        return @bitCast(byte);
    }

    pub fn format(self: Zone, allocator: std.mem.Allocator) ![]const u8 {
        var parts = std.ArrayList([]const u8).init(allocator);
        defer parts.deinit();

        if (self.url) try parts.append("URL");
        if (self.args) try parts.append("ARGS");
        if (self.body) try parts.append("BODY");
        if (self.cookie) try parts.append("COOKIE");
        if (self.header) try parts.append("HDR");
        if (self.user_agent) try parts.append("UA");
        if (self.referer) try parts.append("REF");

        if (parts.items.len == 0) return "-";
        return try std.mem.join(allocator, ",", parts.items);
    }
};

pub const Header = struct {
    magic: [4]u8,
    version: u16,
    payload_count: u32,
    tamper_count: u16,
    waf_count: u16,
    payload_offset: u64,
    tamper_offset: u64,
    waf_offset: u64,
    string_table_offset: u64,
};

pub const PayloadRecord = struct {
    id: u64,
    category: Category,
    zones: Zone,
    blocked_expected: bool,
    source_id: u32,
    payload_hash: [8]u8,
    payload_len: u16,
    preview: []const u8,
};

pub const TamperRecord = struct {
    id: u16,
    category: TamperCategory,
    deterministic: bool,
    name: []const u8,
};

pub const WafRecord = struct {
    id: u16,
    name_offset: u32,
    name: []const u8,
    header_pattern_count: u8,
    body_pattern_count: u8,
    status_codes: [4]u16,
};

pub const Database = struct {
    data: []align(4096) const u8,
    payload_data: ?[]align(4096) const u8,
    header: Header,

    pub fn open(db_path: []const u8, payloads_path: ?[]const u8) !Database {
        const db_file = try fs.cwd().openFile(db_path, .{});
        defer db_file.close();

        const db_stat = try db_file.stat();
        const data = try std.posix.mmap(
            null,
            db_stat.size,
            std.posix.PROT.READ,
            .{ .TYPE = .SHARED },
            db_file.handle,
            0,
        );

        var payload_data: ?[]align(4096) const u8 = null;
        if (payloads_path) |p_path| {
            const p_file = fs.cwd().openFile(p_path, .{}) catch null;
            if (p_file) |pf| {
                defer pf.close();
                const p_stat = try pf.stat();
                payload_data = try std.posix.mmap(
                    null,
                    p_stat.size,
                    std.posix.PROT.READ,
                    .{ .TYPE = .SHARED },
                    pf.handle,
                    0,
                );
            }
        }

        const header = Header{
            .magic = data[0..4].*,
            .version = mem.readInt(u16, data[4..6], .little),
            .payload_count = mem.readInt(u32, data[6..10], .little),
            .tamper_count = mem.readInt(u16, data[10..12], .little),
            .waf_count = mem.readInt(u16, data[12..14], .little),
            .payload_offset = mem.readInt(u64, data[16..24], .little),
            .tamper_offset = mem.readInt(u64, data[24..32], .little),
            .waf_offset = mem.readInt(u64, data[32..40], .little),
            .string_table_offset = mem.readInt(u64, data[40..48], .little),
        };

        if (!mem.eql(u8, &header.magic, MAGIC)) {
            return error.InvalidMagic;
        }
        if (header.version != VERSION) {
            return error.VersionMismatch;
        }

        return Database{
            .data = data,
            .payload_data = payload_data,
            .header = header,
        };
    }

    pub fn close(self: *Database) void {
        std.posix.munmap(self.data);
        if (self.payload_data) |pd| {
            std.posix.munmap(pd);
        }
    }

    pub fn getPayload(self: *const Database, id: u32) ?PayloadRecord {
        if (id >= self.header.payload_count) return null;

        const offset = self.header.payload_offset + id * PAYLOAD_RECORD_SIZE;
        const record = self.data[offset .. offset + PAYLOAD_RECORD_SIZE];

        const preview_end = blk: {
            var end: usize = 40;
            for (0..40) |i| {
                if (record[25 + i] == 0) {
                    end = i;
                    break;
                }
            }
            break :blk end;
        };

        return PayloadRecord{
            .id = mem.readInt(u64, record[0..8], .little),
            .category = @enumFromInt(record[8]),
            .zones = Zone.fromByte(record[9]),
            .blocked_expected = record[10] != 0,
            .source_id = mem.readInt(u32, record[11..15], .little),
            .payload_hash = record[15..23].*,
            .payload_len = mem.readInt(u16, record[23..25], .little),
            .preview = record[25 .. 25 + preview_end],
        };
    }

    pub fn getFullPayload(self: *const Database, id: u32) ?[]const u8 {
        const pd = self.payload_data orelse return null;
        if (id >= self.header.payload_count) return null;

        const offset_pos = 8 + id * 8;
        const offset = mem.readInt(u64, pd[offset_pos..][0..8], .little);
        const length = mem.readInt(u32, pd[offset..][0..4], .little);

        return pd[offset + 4 .. offset + 4 + length];
    }

    pub fn getTamper(self: *const Database, id: u16) ?TamperRecord {
        if (id >= self.header.tamper_count) return null;

        const offset = self.header.tamper_offset + id * TAMPER_RECORD_SIZE;
        const record = self.data[offset .. offset + TAMPER_RECORD_SIZE];

        const name_end = blk: {
            var end: usize = 32;
            for (0..32) |i| {
                if (record[4 + i] == 0) {
                    end = i;
                    break;
                }
            }
            break :blk end;
        };

        return TamperRecord{
            .id = mem.readInt(u16, record[0..2], .little),
            .category = @enumFromInt(record[2]),
            .deterministic = record[3] != 0,
            .name = record[4 .. 4 + name_end],
        };
    }

    pub fn getWaf(self: *const Database, id: u16) ?WafRecord {
        if (id >= self.header.waf_count) return null;

        const offset = self.header.waf_offset + id * WAF_RECORD_SIZE;
        const record = self.data[offset .. offset + WAF_RECORD_SIZE];

        const name_end = blk: {
            var end: usize = 48;
            for (0..48) |i| {
                if (record[6 + i] == 0) {
                    end = i;
                    break;
                }
            }
            break :blk end;
        };

        return WafRecord{
            .id = mem.readInt(u16, record[0..2], .little),
            .name_offset = mem.readInt(u32, record[2..6], .little),
            .name = record[6 .. 6 + name_end],
            .header_pattern_count = record[54],
            .body_pattern_count = record[55],
            .status_codes = .{
                mem.readInt(u16, record[56..58], .little),
                mem.readInt(u16, record[58..60], .little),
                mem.readInt(u16, record[60..62], .little),
                mem.readInt(u16, record[62..64], .little),
            },
        };
    }

    pub fn payloadIterator(self: *const Database) PayloadIterator {
        return PayloadIterator{ .db = self, .index = 0 };
    }

    pub fn tamperIterator(self: *const Database) TamperIterator {
        return TamperIterator{ .db = self, .index = 0 };
    }

    pub fn wafIterator(self: *const Database) WafIterator {
        return WafIterator{ .db = self, .index = 0 };
    }
};

pub const PayloadIterator = struct {
    db: *const Database,
    index: u32,

    pub fn next(self: *PayloadIterator) ?PayloadRecord {
        if (self.index >= self.db.header.payload_count) return null;
        const record = self.db.getPayload(self.index);
        self.index += 1;
        return record;
    }

    pub fn filter(self: *PayloadIterator, category: Category) ?PayloadRecord {
        while (self.next()) |record| {
            if (record.category == category) return record;
        }
        return null;
    }
};

pub const TamperIterator = struct {
    db: *const Database,
    index: u16,

    pub fn next(self: *TamperIterator) ?TamperRecord {
        if (self.index >= self.db.header.tamper_count) return null;
        const record = self.db.getTamper(self.index);
        self.index += 1;
        return record;
    }
};

pub const WafIterator = struct {
    db: *const Database,
    index: u16,

    pub fn next(self: *WafIterator) ?WafRecord {
        if (self.index >= self.db.header.waf_count) return null;
        const record = self.db.getWaf(self.index);
        self.index += 1;
        return record;
    }
};
