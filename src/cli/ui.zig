const std = @import("std");
const io = std.io;

pub const Color = enum {
    reset,
    bold,
    dim,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    bg_red,
    bg_green,
    bg_yellow,

    pub fn code(self: Color) []const u8 {
        return switch (self) {
            .reset => "\x1b[0m",
            .bold => "\x1b[1m",
            .dim => "\x1b[2m",
            .red => "\x1b[31m",
            .green => "\x1b[32m",
            .yellow => "\x1b[33m",
            .blue => "\x1b[34m",
            .magenta => "\x1b[35m",
            .cyan => "\x1b[36m",
            .white => "\x1b[37m",
            .bg_red => "\x1b[41m",
            .bg_green => "\x1b[42m",
            .bg_yellow => "\x1b[43m",
        };
    }
};

pub fn style(writer: anytype, color: Color, text: []const u8) !void {
    try writer.print("{s}{s}{s}", .{ color.code(), text, Color.reset.code() });
}

pub fn styleFmt(writer: anytype, color: Color, comptime fmt: []const u8, args: anytype) !void {
    try writer.writeAll(color.code());
    try writer.print(fmt, args);
    try writer.writeAll(Color.reset.code());
}

pub const banner =
    \\
    \\[cyan]                              ░██    ░██                      ░██[reset]
    \\[cyan]                              ░██                             ░██[reset]
    \\[cyan] ░███████   ░███████  ░██░████ ░████████ ░██ ░███████   ░███████  ░██[reset]
    \\[cyan]░██    ░██ ░██    ░██ ░███        ░██    ░██░██        ░██    ░██ ░██[reset]
    \\[cyan]░██        ░██    ░██ ░██         ░██    ░██ ░███████  ░██    ░██ ░██[reset]
    \\[cyan]░██    ░██ ░██    ░██ ░██         ░██    ░██       ░██ ░██    ░██ ░██[reset]
    \\[cyan] ░███████   ░███████  ░██          ░████ ░██ ░███████   ░███████  ░██[reset]
    \\
    \\[bold][yellow]  WAF Bypass & Normalization Stress Tester[reset]
    \\[dim]  Rewritten in Zig for maximum performance[reset]
    \\
;

pub fn printBanner(writer: anytype) !void {
    var i: usize = 0;
    while (i < banner.len) {
        if (banner[i] == '[') {
            const end = std.mem.indexOfScalarPos(u8, banner, i + 1, ']') orelse {
                try writer.writeByte(banner[i]);
                i += 1;
                continue;
            };
            const tag = banner[i + 1 .. end];

            if (std.mem.eql(u8, tag, "cyan")) {
                try writer.writeAll(Color.cyan.code());
            } else if (std.mem.eql(u8, tag, "yellow")) {
                try writer.writeAll(Color.yellow.code());
            } else if (std.mem.eql(u8, tag, "bold")) {
                try writer.writeAll(Color.bold.code());
            } else if (std.mem.eql(u8, tag, "dim")) {
                try writer.writeAll(Color.dim.code());
            } else if (std.mem.eql(u8, tag, "reset")) {
                try writer.writeAll(Color.reset.code());
            } else {
                try writer.writeByte('[');
                try writer.writeAll(tag);
                try writer.writeByte(']');
            }
            i = end + 1;
        } else {
            try writer.writeByte(banner[i]);
            i += 1;
        }
    }
}

pub fn printBox(writer: anytype, title: []const u8, width: usize) !void {
    try writer.writeAll(Color.cyan.code());
    try writer.writeAll("╔");
    for (0..width - 2) |_| try writer.writeAll("═");
    try writer.writeAll("╗\n");

    try writer.writeAll("║ ");
    try writer.writeAll(Color.bold.code());
    try writer.writeAll(title);
    try writer.writeAll(Color.cyan.code());
    const padding = width - 4 - title.len;
    for (0..padding) |_| try writer.writeAll(" ");
    try writer.writeAll(" ║\n");

    try writer.writeAll("╚");
    for (0..width - 2) |_| try writer.writeAll("═");
    try writer.writeAll("╝");
    try writer.writeAll(Color.reset.code());
    try writer.writeAll("\n");
}

pub fn printSection(writer: anytype, title: []const u8) !void {
    try writer.writeAll("\n");
    try writer.writeAll(Color.bold.code());
    try writer.writeAll(Color.cyan.code());
    try writer.writeAll("▸ ");
    try writer.writeAll(title);
    try writer.writeAll(Color.reset.code());
    try writer.writeAll("\n");
}

pub fn printKeyValue(writer: anytype, key: []const u8, value: []const u8) !void {
    try writer.writeAll("  ");
    try writer.writeAll(Color.dim.code());
    try writer.writeAll(key);
    try writer.writeAll(": ");
    try writer.writeAll(Color.reset.code());
    try writer.writeAll(value);
    try writer.writeAll("\n");
}

pub fn printSuccess(writer: anytype, msg: []const u8) !void {
    try writer.writeAll(Color.green.code());
    try writer.writeAll("✓ ");
    try writer.writeAll(Color.reset.code());
    try writer.writeAll(msg);
    try writer.writeAll("\n");
}

pub fn printWarning(writer: anytype, msg: []const u8) !void {
    try writer.writeAll(Color.yellow.code());
    try writer.writeAll("⚠ ");
    try writer.writeAll(Color.reset.code());
    try writer.writeAll(msg);
    try writer.writeAll("\n");
}

pub fn printError(writer: anytype, msg: []const u8) !void {
    try writer.writeAll(Color.red.code());
    try writer.writeAll("✗ ");
    try writer.writeAll(Color.reset.code());
    try writer.writeAll(msg);
    try writer.writeAll("\n");
}

pub fn printInfo(writer: anytype, msg: []const u8) !void {
    try writer.writeAll(Color.blue.code());
    try writer.writeAll("ℹ ");
    try writer.writeAll(Color.reset.code());
    try writer.writeAll(msg);
    try writer.writeAll("\n");
}

pub const TableColumn = struct {
    header: []const u8,
    width: usize,
    alignment: enum { left, right, center } = .left,
};

pub fn printTableHeader(writer: anytype, columns: []const TableColumn) !void {
    try writer.writeAll(Color.bold.code());
    for (columns) |col| {
        try printCell(writer, col.header, col.width, col.alignment);
        try writer.writeAll(" ");
    }
    try writer.writeAll(Color.reset.code());
    try writer.writeAll("\n");

    try writer.writeAll(Color.dim.code());
    for (columns) |col| {
        for (0..col.width) |_| try writer.writeAll("─");
        try writer.writeAll(" ");
    }
    try writer.writeAll(Color.reset.code());
    try writer.writeAll("\n");
}

pub fn printTableRow(writer: anytype, columns: []const TableColumn, values: []const []const u8) !void {
    for (columns, 0..) |col, i| {
        if (i < values.len) {
            try printCell(writer, values[i], col.width, col.alignment);
        } else {
            for (0..col.width) |_| try writer.writeAll(" ");
        }
        try writer.writeAll(" ");
    }
    try writer.writeAll("\n");
}

fn printCell(writer: anytype, text: []const u8, width: usize, alignment: anytype) !void {
    const truncated = if (text.len > width) text[0..width] else text;
    const padding = width -| truncated.len;

    switch (alignment) {
        .left => {
            try writer.writeAll(truncated);
            for (0..padding) |_| try writer.writeAll(" ");
        },
        .right => {
            for (0..padding) |_| try writer.writeAll(" ");
            try writer.writeAll(truncated);
        },
        .center => {
            const left_pad = padding / 2;
            const right_pad = padding - left_pad;
            for (0..left_pad) |_| try writer.writeAll(" ");
            try writer.writeAll(truncated);
            for (0..right_pad) |_| try writer.writeAll(" ");
        },
    }
}

pub fn printProgress(writer: anytype, current: usize, total: usize, width: usize) !void {
    const progress = if (total > 0) (current * width) / total else 0;

    try writer.writeAll("\r");
    try writer.writeAll(Color.cyan.code());
    try writer.writeAll("[");

    for (0..width) |i| {
        if (i < progress) {
            try writer.writeAll("█");
        } else if (i == progress) {
            try writer.writeAll("▓");
        } else {
            try writer.writeAll("░");
        }
    }

    try writer.writeAll("] ");
    try writer.writeAll(Color.reset.code());
    try writer.print("{d}/{d}", .{ current, total });
}

pub fn clearLine(writer: anytype) !void {
    try writer.writeAll("\r\x1b[K");
}
