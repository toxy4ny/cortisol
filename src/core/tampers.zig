const std = @import("std");
const Allocator = std.mem.Allocator;

/// Error set for tamper application process.
/// Allows the caller to handle unknown tamper names explicitly.
pub const TamperError = error{
    UnknownTamper,
};

/// Tamper functions only return Allocator.Error to keep the signature simple.
/// Logic errors (like unknown names) are handled at the chain application level.
pub const TamperFn = *const fn (allocator: Allocator, input: []const u8) Allocator.Error![]u8;

// =============================================================================
// 1. Utilities (Safety & Performance)
// =============================================================================

/// Optimized replacement function.
/// Calculates the exact size beforehand to perform a single allocation.
fn replaceAll(allocator: Allocator, input: []const u8, needle: []const u8, replacement: []const u8) ![]u8 {
    if (needle.len == 0) return allocator.dupe(u8, input);

    const count = std.mem.count(u8, input, needle);
    if (count == 0) return allocator.dupe(u8, input);

    // Pre-calculate exact required size to avoid reallocations
    const base_len = input.len - (count * needle.len);
    const new_len = base_len + (count * replacement.len);

    const result = try allocator.alloc(u8, new_len);
    errdefer allocator.free(result);

    const written = std.mem.replace(u8, input, needle, replacement, result);
    
    // Safety Check: The written length must match our calculation.
    // If this fails, it indicates a logic bug in size calculation.
    std.debug.assert(written == new_len);
    
    return result;
}

fn hexChar(value: u8) u8 {
    const nibble = value & 0x0F;
    return if (nibble < 10) '0' + nibble else 'A' + nibble - 10;
}

// =============================================================================
// 2. Tamper Implementations
// =============================================================================

// --- Encodings ---

pub fn urlencode(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try result.append(c);
        } else {
            try result.appendSlice(&[_]u8{ '%', hexChar(c >> 4), hexChar(c & 0xF) });
        }
    }
    return result.toOwnedSlice();
}

pub fn doubleurlencode(allocator: Allocator, input: []const u8) ![]u8 {
    const first = try urlencode(allocator, input);
    defer allocator.free(first);
    return urlencode(allocator, first);
}

pub fn tripleurlencode(allocator: Allocator, input: []const u8) ![]u8 {
    const first = try urlencode(allocator, input);
    defer allocator.free(first);
    const second = try urlencode(allocator, first);
    defer allocator.free(second);
    return urlencode(allocator, second);
}

pub fn base64encode(allocator: Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.standard;
    const size = std.base64.standard.Encoder.calcSize(input.len);
    const result = try allocator.alloc(u8, size);
    _ = encoder.Encoder.encode(result, input);
    return result;
}

pub fn urlencodeall(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    for (input) |c| {
        try result.appendSlice(&[_]u8{ '%', hexChar(c >> 4), hexChar(c & 0xF) });
    }
    return result.toOwnedSlice();
}

pub fn htmlencodeall(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    for (input) |c| {
        try result.appendSlice("&#x");
        try result.append(hexChar(c >> 4));
        try result.append(hexChar(c & 0xF));
        try result.append(';');
    }
    return result.toOwnedSlice();
}

// --- Case Manipulation ---

pub fn uppercase(allocator: Allocator, input: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, input.len);
    for (input, 0..) |c, i| result[i] = std.ascii.toUpper(c);
    return result;
}

pub fn lowercase(allocator: Allocator, input: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, input.len);
    for (input, 0..) |c, i| result[i] = std.ascii.toLower(c);
    return result;
}

/// Uses OS CSPRNG (std.crypto.random) for unpredictable randomness.
/// Use this for actual security scanning.
pub fn randomcase(allocator: Allocator, input: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, input.len);
    const rand = std.crypto.random;
    for (input, 0..) |c, i| {
        result[i] = if (rand.boolean()) std.ascii.toUpper(c) else std.ascii.toLower(c);
    }
    return result;
}

/// Uses a seeded PRNG for reproducible results.
/// Useful for testing and debugging.
pub fn randomcaseSeeded(allocator: Allocator, input: []const u8, seed: u64) ![]u8 {
    const result = try allocator.alloc(u8, input.len);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    for (input, 0..) |c, i| {
        result[i] = if (rand.boolean()) std.ascii.toUpper(c) else std.ascii.toLower(c);
    }
    return result;
}

// --- SQL Injection Specific ---

pub fn space2comment(allocator: Allocator, input: []const u8) ![]u8 {
    return replaceAll(allocator, input, " ", "/**/");
}

pub fn space2plus(allocator: Allocator, input: []const u8) ![]u8 {
    return replaceAll(allocator, input, " ", "+");
}

pub fn space2null(allocator: Allocator, input: []const u8) ![]u8 {
    return replaceAll(allocator, input, " ", "%00");
}

pub fn space2hash(allocator: Allocator, input: []const u8) ![]u8 {
    return replaceAll(allocator, input, " ", "%23%0A");
}

pub fn space2doubledashes(allocator: Allocator, input: []const u8) ![]u8 {
    return replaceAll(allocator, input, " ", "--");
}

pub fn appendnull(allocator: Allocator, input: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, input.len + 3);
    @memcpy(result[0..input.len], input);
    @memcpy(result[input.len..], "%00");
    return result;
}

pub fn prependnull(allocator: Allocator, input: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, input.len + 3);
    @memcpy(result[0..3], "%00");
    @memcpy(result[3..], input);
    return result;
}

pub fn apostrephemask(allocator: Allocator, input: []const u8) ![]u8 {
    return replaceAll(allocator, input, "'", "%EF%BC%87");
}

pub fn apostrephenullify(allocator: Allocator, input: []const u8) ![]u8 {
    return replaceAll(allocator, input, "'", "%00%27");
}

pub fn escapequotes(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    for (input) |c| {
        if (c == '\'' or c == '"') try result.append('\\');
        try result.append(c);
    }
    return result.toOwnedSlice();
}

pub fn booleanmask(allocator: Allocator, input: []const u8) ![]u8 {
    const tmp = try replaceAll(allocator, input, " or ", " || ");
    defer allocator.free(tmp);
    const tmp2 = try replaceAll(allocator, tmp, " OR ", " || ");
    defer allocator.free(tmp2);
    const tmp3 = try replaceAll(allocator, tmp2, " and ", " && ");
    defer allocator.free(tmp3);
    return replaceAll(allocator, tmp3, " AND ", " && ");
}

// --- WAF Specific (Optimized) ---

pub fn modsec(allocator: Allocator, input: []const u8) ![]u8 {
    const prefix = "/*!00000";
    const suffix = "*/";
    const result = try allocator.alloc(u8, prefix.len + input.len + suffix.len);
    @memcpy(result[0..prefix.len], prefix);
    @memcpy(result[prefix.len .. prefix.len + input.len], input);
    @memcpy(result[prefix.len + input.len ..], suffix);
    return result;
}

pub fn modsecspace2comment(allocator: Allocator, input: []const u8) ![]u8 {
    const spaced = try space2comment(allocator, input);
    defer allocator.free(spaced);
    return modsec(allocator, spaced);
}

// Optimization: Single-pass replacement using switch for better performance
pub fn level1usingutf8(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    for (input) |c| {
        switch (c) {
            '<' => try result.appendSlice("%C0%BC"),
            '>' => try result.appendSlice("%C0%BE"),
            '\'' => try result.appendSlice("%C0%A7"),
            '"' => try result.appendSlice("%C0%A2"),
            else => try result.append(c),
        }
    }
    return result.toOwnedSlice();
}

pub fn level2usingutf8(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    for (input) |c| {
        switch (c) {
            '<' => try result.appendSlice("%E0%80%BC"),
            '>' => try result.appendSlice("%E0%80%BE"),
            '\'' => try result.appendSlice("%E0%80%A7"),
            '"' => try result.appendSlice("%E0%80%A2"),
            else => try result.append(c),
        }
    }
    return result.toOwnedSlice();
}

pub fn level3usingutf8(allocator: Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    for (input) |c| {
        switch (c) {
            '<' => try result.appendSlice("%F0%80%80%BC"),
            '>' => try result.appendSlice("%F0%80%80%BE"),
            '\'' => try result.appendSlice("%F0%80%80%A7"),
            '"' => try result.appendSlice("%F0%80%80%A2"),
            else => try result.append(c),
        }
    }
    return result.toOwnedSlice();
}

// =============================================================================
// 3. Registry & API
// =============================================================================

pub const TamperEntry = struct {
    name: []const u8,
    func: TamperFn,
    category: []const u8,
    deterministic: bool,
};

pub const tampers = [_]TamperEntry{
    .{ .name = "urlencode", .func = urlencode, .category = "ENCODING", .deterministic = true },
    .{ .name = "doubleurlencode", .func = doubleurlencode, .category = "ENCODING", .deterministic = true },
    .{ .name = "tripleurlencode", .func = tripleurlencode, .category = "ENCODING", .deterministic = true },
    .{ .name = "urlencodeall", .func = urlencodeall, .category = "ENCODING", .deterministic = true },
    .{ .name = "base64encode", .func = base64encode, .category = "ENCODING", .deterministic = true },
    .{ .name = "htmlencodeall", .func = htmlencodeall, .category = "ENCODING", .deterministic = true },
    .{ .name = "uppercase", .func = uppercase, .category = "CASE", .deterministic = true },
    .{ .name = "lowercase", .func = lowercase, .category = "CASE", .deterministic = true },
    // Marked as non-deterministic
    .{ .name = "randomcase", .func = randomcase, .category = "CASE", .deterministic = false },
    .{ .name = "space2comment", .func = space2comment, .category = "SPACE", .deterministic = true },
    .{ .name = "space2plus", .func = space2plus, .category = "SPACE", .deterministic = true },
    .{ .name = "space2null", .func = space2null, .category = "SPACE", .deterministic = true },
    .{ .name = "space2hash", .func = space2hash, .category = "SPACE", .deterministic = true },
    .{ .name = "space2doubledashes", .func = space2doubledashes, .category = "SPACE", .deterministic = true },
    .{ .name = "appendnull", .func = appendnull, .category = "NULL", .deterministic = true },
    .{ .name = "prependnull", .func = prependnull, .category = "NULL", .deterministic = true },
    .{ .name = "apostrephemask", .func = apostrephemask, .category = "QUOTE", .deterministic = true },
    .{ .name = "apostrephenullify", .func = apostrephenullify, .category = "QUOTE", .deterministic = true },
    .{ .name = "escapequotes", .func = escapequotes, .category = "QUOTE", .deterministic = true },
    .{ .name = "booleanmask", .func = booleanmask, .category = "KEYWORD", .deterministic = true },
    .{ .name = "modsec", .func = modsec, .category = "WRAPPER", .deterministic = true },
    .{ .name = "modsecspace2comment", .func = modsecspace2comment, .category = "WRAPPER", .deterministic = true },
    .{ .name = "level1usingutf8", .func = level1usingutf8, .category = "UNICODE", .deterministic = true },
    .{ .name = "level2usingutf8", .func = level2usingutf8, .category = "UNICODE", .deterministic = true },
    .{ .name = "level3usingutf8", .func = level3usingutf8, .category = "UNICODE", .deterministic = true },
};

pub fn getTamperEntryByName(name: []const u8) ?TamperEntry {
    for (tampers) |t| {
        if (std.mem.eql(u8, t.name, name)) return t;
    }
    return null;
}

pub fn getTamperByName(name: []const u8) ?TamperFn {
    if (getTamperEntryByName(name)) |entry| return entry.func;
    return null;
}

/// Validates a chain of tamper names.
/// Returns the index of the first unknown tamper name, or null if all are valid.
/// Useful for providing CLI feedback before execution.
pub fn validateTamperChain(chain: []const []const u8) ?usize {
    for (chain, 0..) |name, i| {
        if (getTamperEntryByName(name) == null) return i;
    }
    return null;
}

/// Applies a chain of tampers to the input.
/// Returns error.UnknownTamper if a name is invalid (typo safety).
pub fn applyTamperChain(allocator: Allocator, input: []const u8, chain: []const []const u8) (Allocator.Error || TamperError)![]u8 {
    var current = try allocator.dupe(u8, input);
    errdefer allocator.free(current);

    for (chain) |name| {
        const entry = getTamperEntryByName(name) orelse return TamperError.UnknownTamper;
        
        const next = try entry.func(allocator, current);
        allocator.free(current);
        current = next;
    }

    return current;
}

/// Checks if the chain contains any non-deterministic tampers (e.g., randomcase).
/// Useful for warning the user about result reproducibility.
pub fn chainHasNondeterministic(chain: []const []const u8) bool {
    for (chain) |name| {
        if (getTamperEntryByName(name)) |t| {
            if (!t.deterministic) return true;
        }
    }
    return false;
}
