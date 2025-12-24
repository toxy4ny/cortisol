const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const process = std.process;

const database = @import("core/database.zig");
const scanner = @import("core/scanner.zig");
const tampers = @import("core/tampers.zig");
const ui = @import("cli/ui.zig");

const version = "0.1.0";

const Args = struct {
    target: ?[]const u8 = null,
    param: []const u8 = "id",
    attack: ?[]const u8 = null,
    tamper: ?[]const u8 = null,
    output: ?[]const u8 = null,
    verbose: bool = false,
    db_path: []const u8 = "cortisol.db",
    limit: u32 = 50,

    // Subcommands
    show_help: bool = false,
    show_version: bool = false,
    list_payloads: bool = false,
    list_tampers: bool = false,
    list_wafs: bool = false,
    db_stats: bool = false,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = io.getStdOut().writer();
    const stderr = io.getStdErr().writer();

    const args = parseArgs(allocator) catch |err| {
        try stderr.print("Error parsing arguments: {s}\n", .{@errorName(err)});
        try printUsage(stderr);
        return;
    };

    if (args.show_help) {
        try printUsage(stdout);
        return;
    }

    if (args.show_version) {
        try stdout.print("cortisol {s}\n", .{version});
        return;
    }

    // Open database
    var db = database.Database.open(args.db_path, "cortisol.payloads") catch |err| {
        try stderr.print("Error: Cannot open database '{s}': {s}\n", .{ args.db_path, @errorName(err) });
        try stderr.print("Run: python tools/dbgen.py\n", .{});
        return;
    };
    defer db.close();

    // Handle subcommands
    if (args.db_stats) {
        try showDbStats(stdout, &db);
        return;
    }

    if (args.list_payloads) {
        try listPayloads(stdout, allocator, &db, args.attack, args.limit);
        return;
    }

    if (args.list_tampers) {
        try listTampers(stdout, &db);
        return;
    }

    if (args.list_wafs) {
        try listWafs(stdout, &db);
        return;
    }

    // Scan mode requires target
    if (args.target == null) {
        try ui.printBanner(stdout);
        try stdout.writeAll("\n");
        try ui.printError(stdout, "No target specified. Use -t <url> or --help for usage.");
        return;
    }

    // Run scan
    try runScan(stdout, allocator, &db, args);
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
    var args = Args{};
    var arg_iter = try process.argsWithAllocator(allocator);
    defer arg_iter.deinit();

    _ = arg_iter.skip(); // Skip program name

    while (arg_iter.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            args.show_help = true;
        } else if (mem.eql(u8, arg, "-V") or mem.eql(u8, arg, "--version")) {
            args.show_version = true;
        } else if (mem.eql(u8, arg, "-t") or mem.eql(u8, arg, "--target")) {
            args.target = arg_iter.next();
        } else if (mem.eql(u8, arg, "-p") or mem.eql(u8, arg, "--param")) {
            args.param = arg_iter.next() orelse "id";
        } else if (mem.eql(u8, arg, "-a") or mem.eql(u8, arg, "--attack")) {
            args.attack = arg_iter.next();
        } else if (mem.eql(u8, arg, "-T") or mem.eql(u8, arg, "--tamper")) {
            args.tamper = arg_iter.next();
        } else if (mem.eql(u8, arg, "-o") or mem.eql(u8, arg, "--output")) {
            args.output = arg_iter.next();
        } else if (mem.eql(u8, arg, "-v") or mem.eql(u8, arg, "--verbose")) {
            args.verbose = true;
        } else if (mem.eql(u8, arg, "--db")) {
            args.db_path = arg_iter.next() orelse "cortisol.db";
        } else if (mem.eql(u8, arg, "-n") or mem.eql(u8, arg, "--limit")) {
            if (arg_iter.next()) |n| {
                args.limit = std.fmt.parseInt(u32, n, 10) catch 50;
            }
        } else if (mem.eql(u8, arg, "--payloads")) {
            args.list_payloads = true;
        } else if (mem.eql(u8, arg, "--tampers")) {
            args.list_tampers = true;
        } else if (mem.eql(u8, arg, "--wafs")) {
            args.list_wafs = true;
        } else if (mem.eql(u8, arg, "--stats")) {
            args.db_stats = true;
        }
    }

    return args;
}

fn printUsage(writer: anytype) !void {
    try ui.printBanner(writer);
    try writer.writeAll(
        \\
        \\[1mUSAGE[0m
        \\    cortisol [OPTIONS] -t <target>
        \\
        \\[1mOPTIONS[0m
        \\    -t, --target <url>     Target URL (required for scan)
        \\    -p, --param <name>     Parameter to inject (default: id)
        \\    -a, --attack <type>    Attack type: sqli, xss, lfi, ssrf, ssti, rce
        \\    -T, --tamper <name>    Tamper function to apply
        \\    -o, --output <file>    Save results to JSONL file
        \\    -n, --limit <num>      Max payloads to test (default: 50)
        \\    -v, --verbose          Show detailed output
        \\    --db <path>            Path to cortisol.db (default: cortisol.db)
        \\
        \\[1mINFO COMMANDS[0m
        \\    --stats                Show database statistics
        \\    --payloads             List available payloads
        \\    --tampers              List available tamper functions
        \\    --wafs                 List WAF signatures
        \\    -h, --help             Show this help
        \\    -V, --version          Show version
        \\
        \\[1mEXAMPLES[0m
        \\    cortisol -t https://target.com/page -p id -a sqli
        \\    cortisol -t https://target.com/search -p q -a xss -T doubleurlencode
        \\    cortisol --payloads -a sqli
        \\    cortisol --tampers
        \\
    );
}

fn showDbStats(writer: anytype, db: *database.Database) !void {
    try ui.printBanner(writer);
    try writer.writeAll("\n");
    try ui.printBox(writer, "Database Statistics", 50);
    try writer.writeAll("\n");

    try ui.printKeyValue(writer, "Magic", &db.header.magic);

    var version_buf: [16]u8 = undefined;
    const version_str = std.fmt.bufPrint(&version_buf, "{d}", .{db.header.version}) catch "?";
    try ui.printKeyValue(writer, "Version", version_str);

    var payload_buf: [16]u8 = undefined;
    const payload_str = std.fmt.bufPrint(&payload_buf, "{d}", .{db.header.payload_count}) catch "?";
    try ui.printKeyValue(writer, "Payloads", payload_str);

    var tamper_buf: [16]u8 = undefined;
    const tamper_str = std.fmt.bufPrint(&tamper_buf, "{d}", .{db.header.tamper_count}) catch "?";
    try ui.printKeyValue(writer, "Tampers", tamper_str);

    var waf_buf: [16]u8 = undefined;
    const waf_str = std.fmt.bufPrint(&waf_buf, "{d}", .{db.header.waf_count}) catch "?";
    try ui.printKeyValue(writer, "WAF Sigs", waf_str);

    try writer.writeAll("\n");
    try ui.printSuccess(writer, "Database loaded successfully");
}

fn listPayloads(writer: anytype, allocator: std.mem.Allocator, db: *database.Database, attack_filter: ?[]const u8, limit: u32) !void {
    try ui.printBanner(writer);
    try writer.writeAll("\n");

    const category: ?database.Category = if (attack_filter) |filter| blk: {
        if (mem.eql(u8, filter, "sqli")) break :blk .sqli;
        if (mem.eql(u8, filter, "xss")) break :blk .xss;
        if (mem.eql(u8, filter, "lfi")) break :blk .lfi;
        if (mem.eql(u8, filter, "ssrf")) break :blk .ssrf;
        if (mem.eql(u8, filter, "ssti")) break :blk .ssti;
        if (mem.eql(u8, filter, "rce")) break :blk .rce;
        if (mem.eql(u8, filter, "nosqli")) break :blk .nosqli;
        break :blk null;
    } else null;

    const title = if (attack_filter) |f|
        try std.fmt.allocPrint(allocator, "Payloads ({s})", .{f})
    else
        try allocator.dupe(u8, "Payloads (all)");
    defer allocator.free(title);

    try ui.printSection(writer, title);

    const columns = [_]ui.TableColumn{
        .{ .header = "ID", .width = 5, .alignment = .right },
        .{ .header = "Category", .width = 12, .alignment = .left },
        .{ .header = "Len", .width = 5, .alignment = .right },
        .{ .header = "Preview", .width = 50, .alignment = .left },
    };
    try ui.printTableHeader(writer, &columns);

    var count: u32 = 0;
    var iter = db.payloadIterator();
    while (iter.next()) |payload| {
        if (category != null and payload.category != category.?) continue;
        if (count >= limit) break;

        var id_buf: [16]u8 = undefined;
        const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{payload.id}) catch "?";

        var len_buf: [16]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{payload.payload_len}) catch "?";

        const values = [_][]const u8{
            id_str,
            payload.category.toString(),
            len_str,
            payload.preview,
        };
        try ui.printTableRow(writer, &columns, &values);
        count += 1;
    }

    try writer.writeAll("\n");
    var count_buf: [64]u8 = undefined;
    const count_msg = std.fmt.bufPrint(&count_buf, "Showing {d} payloads (total: {d})", .{ count, db.header.payload_count }) catch "?";
    try ui.printInfo(writer, count_msg);
}

fn listTampers(writer: anytype, db: *database.Database) !void {
    try ui.printBanner(writer);
    try writer.writeAll("\n");
    try ui.printSection(writer, "Available Tamper Functions");

    const columns = [_]ui.TableColumn{
        .{ .header = "ID", .width = 3, .alignment = .right },
        .{ .header = "Name", .width = 24, .alignment = .left },
        .{ .header = "Category", .width = 12, .alignment = .left },
        .{ .header = "Det", .width = 3, .alignment = .center },
    };
    try ui.printTableHeader(writer, &columns);

    var iter = db.tamperIterator();
    while (iter.next()) |t| {
        var id_buf: [8]u8 = undefined;
        const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{t.id}) catch "?";

        const det_str: []const u8 = if (t.deterministic) "✓" else "✗";

        const values = [_][]const u8{
            id_str,
            t.name,
            t.category.toString(),
            det_str,
        };
        try ui.printTableRow(writer, &columns, &values);
    }

    try writer.writeAll("\n");
    try ui.printInfo(writer, "Det = Deterministic (produces same output for same input)");
}

fn listWafs(writer: anytype, db: *database.Database) !void {
    try ui.printBanner(writer);
    try writer.writeAll("\n");
    try ui.printSection(writer, "WAF Signatures");

    const columns = [_]ui.TableColumn{
        .{ .header = "ID", .width = 3, .alignment = .right },
        .{ .header = "Name", .width = 40, .alignment = .left },
        .{ .header = "Headers", .width = 7, .alignment = .right },
        .{ .header = "Body", .width = 5, .alignment = .right },
    };
    try ui.printTableHeader(writer, &columns);

    var iter = db.wafIterator();
    while (iter.next()) |w| {
        var id_buf: [8]u8 = undefined;
        const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{w.id}) catch "?";

        var hdr_buf: [8]u8 = undefined;
        const hdr_str = std.fmt.bufPrint(&hdr_buf, "{d}", .{w.header_pattern_count}) catch "?";

        var body_buf: [8]u8 = undefined;
        const body_str = std.fmt.bufPrint(&body_buf, "{d}", .{w.body_pattern_count}) catch "?";

        const values = [_][]const u8{
            id_str,
            w.name,
            hdr_str,
            body_str,
        };
        try ui.printTableRow(writer, &columns, &values);
    }
}

const ScanContext = struct {
    mutex: *std.Thread.Mutex,
    hits: *u32,
    count: *u32,
    writer: std.fs.File.Writer,
    scan: *scanner.Scanner,
    payload_id: u32,
    category_name: []const u8,
    columns: []const ui.TableColumn,
    verbose: bool,
};

fn scanWorker(ctx: ScanContext) void {
    const result = ctx.scan.scanPayload(ctx.payload_id) catch |err| {
        if (ctx.verbose) {
            ctx.mutex.lock();
            defer ctx.mutex.unlock();
            ui.printWarning(ctx.writer, @errorName(err)) catch {};
        }
        return;
    };

    var id_buf: [8]u8 = undefined;
    const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{result.payload_id}) catch "?";

    var stat_buf: [8]u8 = undefined;
    const stat_str = std.fmt.bufPrint(&stat_buf, "{d}", .{result.status_code}) catch "?";

    var size_buf: [16]u8 = undefined;
    const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{result.response_size}) catch "?";

    var time_buf: [16]u8 = undefined;
    const time_str = std.fmt.bufPrint(&time_buf, "{d}ms", .{result.response_time_ms}) catch "?";

    const diff_str: []const u8 = if (result.is_different) "✓" else "";

    const values = [_][]const u8{
        id_str,
        ctx.category_name,
        stat_str,
        size_str,
        time_str,
        diff_str,
    };

    ctx.mutex.lock();
    defer ctx.mutex.unlock();

    ctx.count.* += 1;
    if (result.is_different) {
        ctx.writer.writeAll(ui.Color.green.code()) catch {};
        ctx.hits.* += 1;
    }
    ui.printTableRow(ctx.writer, ctx.columns, &values) catch {};
    if (result.is_different) {
        ctx.writer.writeAll(ui.Color.reset.code()) catch {};
    }
}

fn runScan(writer: anytype, allocator: std.mem.Allocator, db: *database.Database, args: Args) !void {
    try ui.printBanner(writer);
    try writer.writeAll("\n");

    // Show scan configuration
    try ui.printSection(writer, "Scan Configuration");
    try ui.printKeyValue(writer, "Target", args.target.?);
    try ui.printKeyValue(writer, "Parameter", args.param);
    if (args.attack) |a| try ui.printKeyValue(writer, "Attack", a);
    if (args.tamper) |t| try ui.printKeyValue(writer, "Tamper", t);

    // Detect WAF
    try writer.writeAll("\n");
    try ui.printSection(writer, "WAF Detection");

    const waf = scanner.detectWaf(allocator, args.target.?) catch |err| blk: {
        try ui.printWarning(writer, @errorName(err));
        break :blk null;
    };

    if (waf) |w| {
        try ui.styleFmt(writer, .yellow, "  Detected: {s}\n", .{w});
    } else {
        try ui.printInfo(writer, "No WAF detected (or unknown)");
    }

    // Setup scanner
    const category: ?database.Category = if (args.attack) |filter| blk: {
        if (mem.eql(u8, filter, "sqli")) break :blk .sqli;
        if (mem.eql(u8, filter, "xss")) break :blk .xss;
        if (mem.eql(u8, filter, "lfi")) break :blk .lfi;
        if (mem.eql(u8, filter, "ssrf")) break :blk .ssrf;
        if (mem.eql(u8, filter, "ssti")) break :blk .ssti;
        if (mem.eql(u8, filter, "rce")) break :blk .rce;
        break :blk null;
    } else null;

    var tamper_list: [1][]const u8 = undefined;
    const tamper_slice: []const []const u8 = if (args.tamper) |t| blk: {
        tamper_list[0] = t;
        break :blk &tamper_list;
    } else &.{};

    const config = scanner.ScanConfig{
        .target_url = args.target.?,
        .param = args.param,
        .category = category,
        .tamper_names = tamper_slice,
        .verbose = args.verbose,
    };

    var scan = scanner.Scanner.init(allocator, config, db);

    // Establish baseline
    try writer.writeAll("\n");
    try ui.printSection(writer, "Establishing Baseline");
    scan.establishBaseline() catch |err| {
        try ui.printError(writer, @errorName(err));
        return;
    };

    var status_buf: [32]u8 = undefined;
    const baseline_msg = std.fmt.bufPrint(&status_buf, "Status: {d}, Size: {d} bytes", .{ scan.baseline_status, scan.baseline_size }) catch "?";
    try ui.printSuccess(writer, baseline_msg);

    // Run scan
    try writer.writeAll("\n");
    try ui.printSection(writer, "Scanning (Concurrent)");

    const columns = [_]ui.TableColumn{
        .{ .header = "ID", .width = 5, .alignment = .right },
        .{ .header = "Category", .width = 10, .alignment = .left },
        .{ .header = "Status", .width = 6, .alignment = .right },
        .{ .header = "Size", .width = 8, .alignment = .right },
        .{ .header = "Time", .width = 6, .alignment = .right },
        .{ .header = "Diff", .width = 4, .alignment = .center },
    };
    try ui.printTableHeader(writer, &columns);

    var count: u32 = 0;
    var hits: u32 = 0;
    var iter = db.payloadIterator();
    
    // Thread pool setup
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator, .n_jobs = 10 });
    defer pool.deinit();
    
    var wg = std.Thread.WaitGroup{};
    var mutex = std.Thread.Mutex{};

    // Cast writer to concrete type for struct embedding
    // const stdout_writer = io.getStdOut().writer(); // In main() it is this type.
    // We assume 'writer' passed in is compatible with std.fs.File.Writer or we need to change struct.
    // Hack: We know main passes getStdOut().writer().
    const file_writer = std.io.getStdOut().writer();

    var dispatched: u32 = 0;
    while (iter.next()) |payload| {
        if (category != null and payload.category != category.?) continue;
        if (dispatched >= args.limit) break;

        wg.start();
        try pool.spawn(scanWorker, .{ScanContext{
            .mutex = &mutex,
            .hits = &hits,
            .count = &count,
            .writer = file_writer,
            .scan = &scan,
            .payload_id = @intCast(payload.id),
            .category_name = payload.category.toString(),
            .columns = &columns,
            .verbose = args.verbose,
        }});
        
        dispatched += 1;
    }
    
    pool.waitAndWork(&wg);

    // Summary
    try writer.writeAll("\n");
    try ui.printSection(writer, "Summary");

    var summary_buf: [128]u8 = undefined;
    const summary = std.fmt.bufPrint(&summary_buf, "Tested {d} payloads, {d} potential bypasses found", .{ count, hits }) catch "?";

    if (hits > 0) {
        try ui.printSuccess(writer, summary);
    } else {
        try ui.printInfo(writer, summary);
    }
}

test "basic test" {
    // Basic compilation test
    _ = database;
    _ = tampers;
    _ = ui;
}
