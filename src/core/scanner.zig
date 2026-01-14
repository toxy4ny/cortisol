const std = @import("std");
const http = std.http;
const Uri = std.Uri;
const Allocator = std.mem.Allocator;

const database = @import("database.zig");
const tampers = @import("tampers.zig");

// Constants for defaults
pub const DEFAULT_TIMEOUT_MS = 10000;
pub const DEFAULT_DELAY_MS = 100;

/// Result of a single payload scan.
/// ⚠️ Lifetime Note:
/// - `payload`: Points to memory owned by the **Database**.
/// - `tamper`: Points to memory owned by **ScanConfig** (tamper_names).
/// - `error_msg`: Points to **static string literals** or @errorName.
/// Ensure these sources remain valid while using ScanResult.
pub const ScanResult = struct {
    payload_id: u32,
    payload: []const u8,
    
    /// Dual purpose field:
    /// - On Success: The name of the last tamper applied.
    /// - On Error (UnknownTamper): The specific name that caused the validation failure.
    /// - On Other Error: null.
    tamper: ?[]const u8,
    
    status_code: u16,
    response_size: usize,
    response_time_ms: u64,
    is_different: bool,
    
    /// Points to static string literals or @errorName (no dynamic allocation).
    error_msg: ?[]const u8,
};

/// Configuration for the scanner.
///
/// ⚠️ LIFETIME WARNING ⚠️
/// This struct uses slices (`[]const u8`) to reference strings.
/// The Scanner does NOT deep-copy these strings during initialization.
/// The caller MUST ensure that the memory backing `target_url`, `param`, and `tamper_names`
/// remains valid for the entire lifetime of the Scanner.
///
/// ❌ DO NOT pass slices to stack-allocated arrays that go out of scope.
/// ✅ DO pass string literals, allocator-owned strings, or global constants.
pub const ScanConfig = struct {
    target_url: []const u8,
    param: []const u8,
    category: ?database.Category = null,
    tamper_names: []const []const u8 = &.{},
    
    // Safety: If false, payload is appended raw (useful if tamper handles encoding).
    // If true, payload is URL-encoded before appending.
    encode_param_value: bool = true,

    // TODO: Implement read/connect timeouts (requires custom client configuration).
    // Currently, this setting is advisory and logs a warning if set.
    timeout_ms: u64 = DEFAULT_TIMEOUT_MS,
    
    delay_ms: u64 = DEFAULT_DELAY_MS,
    max_payloads: ?u32 = null,
    verbose: bool = false,
};

/// ⚠️ WARNING: Scanner contains an http.Client which holds internal state/pointers.
///
/// Usage Pattern:
/// var scanner = Scanner.init(...);
/// defer scanner.deinit();
/// 
/// Do NOT copy this struct by value. Pass by pointer (*Scanner) to functions.
pub const Scanner = struct {
    allocator: Allocator,
    config: ScanConfig,
    db: *database.Database,
    client: http.Client,
    baseline_status: u16,
    baseline_size: usize,

    pub fn init(allocator: Allocator, config: ScanConfig, db: *database.Database) Scanner {
        // Warning for unimplemented feature (Reduced noise: only if changed AND verbose)
        if (config.verbose and config.timeout_ms != DEFAULT_TIMEOUT_MS) {
            std.log.warn("Scanner: Custom timeout_ms ({d}) is set but currently not enforced by the HTTP client.", .{config.timeout_ms});
        }

        return Scanner{
            .allocator = allocator,
            .config = config,
            .db = db,
            .client = http.Client{ .allocator = allocator },
            .baseline_status = 0,
            .baseline_size = 0,
        };
    }

    pub fn deinit(self: *Scanner) void {
        self.client.deinit();
    }

    pub fn establishBaseline(self: *Scanner) !void {
        // Using a random-like string "1" for baseline.
        // Ideally, this should be configurable to avoid accidental matches.
        const url = try self.buildUrl("1");
        defer self.allocator.free(url);

        const result = try self.makeRequest(url);
        self.baseline_status = result.status;
        self.baseline_size = result.size;
    }

    pub fn scanPayload(self: *Scanner, payload_id: u32) !ScanResult {
        // 1. DB Lookup First
        // We need the payload/preview to provide meaningful debug info even if validation fails.
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

        // 2. Pre-validation of Tamper Chain
        // If validation fails, we return the retrieved payload so the user knows WHAT failed.
        if (self.config.tamper_names.len > 0) {
            if (tampers.validateTamperChain(self.config.tamper_names)) |bad_idx| {
                return ScanResult{
                    .payload_id = payload_id,
                    .payload = full_payload, // Return actual payload for debugging
                    .tamper = self.config.tamper_names[bad_idx], // The invalid name
                    .status_code = 0,
                    .response_size = 0,
                    .response_time_ms = 0,
                    .is_different = false,
                    .error_msg = "Unknown Tamper Name",
                };
            }
        }

        // 3. Delay (Applied only before actual processing)
        // We don't sleep for DB misses or configuration errors.
        if (self.config.delay_ms > 0) {
            std.time.sleep(self.config.delay_ms * 1_000_000); // ms to ns
        }

        var final_payload: []u8 = undefined;
        var used_tamper: ?[]const u8 = null;

        // 4. Apply Tampers
        if (self.config.tamper_names.len > 0) {
            final_payload = tampers.applyTamperChain(
                self.allocator,
                full_payload,
                self.config.tamper_names,
            ) catch |err| {
                return ScanResult{
                    .payload_id = payload_id,
                    .payload = full_payload,
                    .tamper = null,
                    .status_code = 0,
                    .response_size = 0,
                    .response_time_ms = 0,
                    .is_different = false,
                    .error_msg = @errorName(err),
                };
            };
            used_tamper = self.config.tamper_names[self.config.tamper_names.len - 1];
        } else {
            final_payload = try self.allocator.dupe(u8, full_payload);
        }
        defer self.allocator.free(final_payload);

        // 5. Build URL & Request
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
        
        // ✅ Idiomatic Zig: Use if-expression to avoid var undefined
        const encoded = if (self.config.encode_param_value)
            try tampers.urlencode(self.allocator, payload)
        else
            try self.allocator.dupe(u8, payload);
        defer self.allocator.free(encoded);
        
        try result.appendSlice(encoded);

        return result.toOwnedSlice();
    }

    const RequestResult = struct {
        status: u16,
        size: usize,
    };

    fn makeRequest(self: *Scanner, url: []const u8) !RequestResult {
        // Reuse self.client (Keep-Alive)
        const uri = try Uri.parse(url);

        var header_buf: [4096]u8 = undefined;
        
        var req = try self.client.open(.GET, uri, .{
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

// Full implementation of detectWaf
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
