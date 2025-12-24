const std = @import("std");
const http = std.http;
const Uri = std.Uri;
const Allocator = std.mem.Allocator;

const database = @import("database.zig");
const tampers = @import("tampers.zig");

pub const ScanResult = struct {
    payload_id: u32,
    payload: []const u8,
    tamper: ?[]const u8,
    status_code: u16,
    response_size: usize,
    response_time_ms: u64,
    is_different: bool,
    error_msg: ?[]const u8,
};

pub const ScanConfig = struct {
    target_url: []const u8,
    param: []const u8,
    category: ?database.Category = null,
    tamper_names: []const []const u8 = &.{},
    timeout_ms: u64 = 10000,
    delay_ms: u64 = 100,
    max_payloads: ?u32 = null,
    verbose: bool = false,
};

pub const Scanner = struct {
    allocator: Allocator,
    config: ScanConfig,
    db: *database.Database,
    baseline_status: u16,
    baseline_size: usize,

    pub fn init(allocator: Allocator, config: ScanConfig, db: *database.Database) Scanner {
        return Scanner{
            .allocator = allocator,
            .config = config,
            .db = db,
            .baseline_status = 0,
            .baseline_size = 0,
        };
    }

    pub fn establishBaseline(self: *Scanner) !void {
        const url = try self.buildUrl("1");
        defer self.allocator.free(url);

        const result = try self.makeRequest(url);
        self.baseline_status = result.status;
        self.baseline_size = result.size;
    }

    pub fn scanPayload(self: *Scanner, payload_id: u32) !ScanResult {
        const payload_record = self.db.getPayload(payload_id) orelse {
            return ScanResult{
                .payload_id = payload_id,
                .payload = "",
                .tamper = null,
                .status_code = 0,
                .response_size = 0,
                .response_time_ms = 0,
                .is_different = false,
                .error_msg = "Payload not found",
            };
        };

        const full_payload = self.db.getFullPayload(payload_id) orelse payload_record.preview;

        var final_payload: []u8 = undefined;
        var used_tamper: ?[]const u8 = null;

        if (self.config.tamper_names.len > 0) {
            final_payload = try tampers.applyTamperChain(
                self.allocator,
                full_payload,
                self.config.tamper_names,
            );
            used_tamper = self.config.tamper_names[self.config.tamper_names.len - 1];
        } else {
            final_payload = try self.allocator.dupe(u8, full_payload);
        }
        defer self.allocator.free(final_payload);

        const url = try self.buildUrl(final_payload);
        defer self.allocator.free(url);

        const start_time = std.time.milliTimestamp();
        const result = self.makeRequest(url) catch |err| {
            return ScanResult{
                .payload_id = payload_id,
                .payload = full_payload,
                .tamper = used_tamper,
                .status_code = 0,
                .response_size = 0,
                .response_time_ms = 0,
                .is_different = false,
                .error_msg = @errorName(err),
            };
        };
        const end_time = std.time.milliTimestamp();

        const size_diff = if (result.size > self.baseline_size)
            result.size - self.baseline_size
        else
            self.baseline_size - result.size;

        const is_different = result.status != self.baseline_status or size_diff > 50;

        return ScanResult{
            .payload_id = payload_id,
            .payload = full_payload,
            .tamper = used_tamper,
            .status_code = result.status,
            .response_size = result.size,
            .response_time_ms = @intCast(end_time - start_time),
            .is_different = is_different,
            .error_msg = null,
        };
    }

    fn buildUrl(self: *Scanner, payload: []const u8) ![]u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();

        try result.appendSlice(self.config.target_url);

        if (std.mem.indexOf(u8, self.config.target_url, "?") == null) {
            try result.append('?');
        } else {
            try result.append('&');
        }

        try result.appendSlice(self.config.param);
        try result.append('=');
        try result.appendSlice(payload);

        return result.toOwnedSlice();
    }

    const RequestResult = struct {
        status: u16,
        size: usize,
    };

    fn makeRequest(self: *Scanner, url: []const u8) !RequestResult {
        var client = http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const uri = try Uri.parse(url);

        var header_buf: [4096]u8 = undefined;
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = &header_buf,
        });
        defer req.deinit();

        try req.send();
        try req.wait();

        var body_size: usize = 0;
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = try req.read(&buf);
            if (n == 0) break;
            body_size += n;
        }

        const status: u16 = @intFromEnum(req.response.status);
        return RequestResult{
            .status = status,
            .size = body_size,
        };
    }
};

pub fn detectWaf(allocator: Allocator, url: []const u8) !?[]const u8 {
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try Uri.parse(url);

    var header_buf: [8192]u8 = undefined;
    var req = try client.open(.GET, uri, .{
        .server_header_buffer = &header_buf,
    });
    defer req.deinit();

    try req.send();
    try req.wait();

    // Read body for signatures
    var body_buf: [8192]u8 = undefined;
    const body_len = try req.readAll(&body_buf);
    const body = body_buf[0..body_len];

    // Check headers
    var iter = req.response.iterateHeaders();
    while (iter.next()) |header| {
        const name = header.name;
        const value = header.value;

        // Cloudflare
        if (std.ascii.eqlIgnoreCase(name, "cf-ray") or
            std.ascii.eqlIgnoreCase(name, "cf-cache-status"))
        {
            return "Cloudflare";
        }

        // AWS
        if (std.ascii.eqlIgnoreCase(name, "x-amz-cf-id") or
            std.ascii.eqlIgnoreCase(name, "x-amz-request-id"))
        {
            return "AWS WAF / CloudFront";
        }

        // Sucuri
        if (std.ascii.eqlIgnoreCase(name, "x-sucuri-id")) {
            return "Sucuri CloudProxy";
        }

        // Imperva
        if (std.ascii.eqlIgnoreCase(name, "x-iinfo") or
            std.ascii.eqlIgnoreCase(name, "x-cdn"))
        {
            return "Imperva / Incapsula";
        }

        // Wordfence
        if (std.ascii.eqlIgnoreCase(name, "x-wordfence")) {
            return "Wordfence";
        }

        // Server header checks
        if (std.ascii.eqlIgnoreCase(name, "server")) {
            if (std.mem.indexOf(u8, value, "cloudflare") != null) {
                return "Cloudflare";
            }
            if (std.mem.indexOf(u8, value, "AkamaiGHost") != null) {
                return "Akamai";
            }
            if (std.mem.indexOf(u8, value, "BigIP") != null or
                std.mem.indexOf(u8, value, "BIG-IP") != null)
            {
                return "F5 BIG-IP ASM";
            }
            if (std.mem.indexOf(u8, value, "sucuri") != null) {
                return "Sucuri CloudProxy";
            }
            if (std.mem.indexOf(u8, value, "mod_security") != null or
                std.mem.indexOf(u8, value, "ModSecurity") != null)
            {
                return "ModSecurity";
            }
        }
    }

    // Check body signatures
    if (std.mem.indexOf(u8, body, "generated by wordfence") != null) {
        return "Wordfence";
    }
    if (std.mem.indexOf(u8, body, "mod_security") != null or
        std.mem.indexOf(u8, body, "ModSecurity") != null)
    {
        return "ModSecurity";
    }
    if (std.mem.indexOf(u8, body, "sucuri") != null) {
        return "Sucuri CloudProxy";
    }
    if (std.mem.indexOf(u8, body, "cloudflare") != null) {
        return "Cloudflare";
    }

    return null;
}
