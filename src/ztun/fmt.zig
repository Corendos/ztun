// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn formatSliceHexSpacedImpl(
    bytes: []const u8,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    const charset = "0123456789ABCDEF";
    _ = fmt;
    _ = options;
    var buf: [4]u8 = undefined;

    buf[0] = '0';
    buf[1] = 'x';

    for (bytes) |c, i| {
        if (i > 0) {
            try writer.writeByte(' ');
        }
        buf[2] = charset[c >> 4];
        buf[3] = charset[c & 15];
        try writer.writeAll(&buf);
    }
}

pub fn formatSliceHexSpaced(bytes: []const u8) std.fmt.Formatter(formatSliceHexSpacedImpl) {
    return .{ .data = bytes };
}
