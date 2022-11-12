// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn writeAllAligned(bytes: []const u8, alignment: usize, writer: anytype) !void {
    try writer.writeAll(bytes);
    const padding = std.mem.alignForward(bytes.len, alignment) - bytes.len;
    try writer.writeByteNTimes(0, padding);
}

pub fn readNoEofAligned(reader: anytype, alignment: usize, buf: []u8) !void {
    try reader.readNoEof(buf);
    const padding = std.mem.alignForward(buf.len, alignment) - buf.len;
    try reader.skipBytes(@as(u64, padding), .{ .buf_size = 16 });
}

test "write all aligned" {
    const str = [_]u8{ 1, 2, 3 };
    var buffer: [128]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try writeAllAligned(&str, 4, stream.writer());
    const written = stream.getWritten();
    try std.testing.expectEqual(@as(usize, 4), written.len);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 0 }, written);
}

test "read all aligned" {
    var buffer = [_]u8{0} ** 128;
    const str = "This is a test";
    std.mem.copy(u8, &buffer, str);
    var stream = std.io.fixedBufferStream(&buffer);

    var output_buffer: [str.len]u8 = undefined;
    try readNoEofAligned(stream.reader(), 4, &output_buffer);
    const pos = try stream.getPos();

    try std.testing.expectEqual(@as(usize, 16), pos);
    try std.testing.expectEqualSlices(u8, str, &output_buffer);
}
