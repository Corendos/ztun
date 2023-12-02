// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const unicode = @import("unicode.zig");

/// Writes the input bytes to the writer and pad with 0 to align the amount written to the given alignment.
pub fn writeAllAligned(bytes: []const u8, alignment: usize, writer: anytype) !void {
    try writer.writeAll(bytes);
    const padding = std.mem.alignForward(usize, bytes.len, alignment) - bytes.len;
    try writer.writeByteNTimes(0, padding);
}

/// Reads enough bytes to fill the buffer (or fail with an error on EOF) and skip bytes to align the amount read
/// to the given alignment.
pub fn readNoEofAligned(reader: anytype, alignment: usize, buf: []u8) !void {
    try reader.readNoEof(buf);
    const padding = std.mem.alignForward(u64, buf.len, alignment) - buf.len;
    try reader.skipBytes(padding, .{ .buf_size = 16 });
}

/// Computes the OpaqueString profile defined in
/// https://www.rfc-editor.org/rfc/rfc8265#section-4.2
pub fn computeOpaqueString(source: []const u8, out: []u8) ![]u8 {
    var stream = std.io.fixedBufferStream(out);
    try writeOpaqueString(source, stream.writer());
    return stream.getWritten();
}

/// Writes the OpaqueString produced by the given source to the writer.
pub fn writeOpaqueString(source: []const u8, writer: anytype) !void {
    // NOTE(Corendos): For now, this will accept only ascii characters
    if (!unicode.isFreeFormAsciiString(source)) return error.InvalidString;
    for (source) |c| {
        // TODO(Corendos): From RFC 8265 Section 4.2.2:
        //                 1. Fullwidth and halfwidth code points MUST NOT be mapped to their decomposition mappings.
        if (unicode.precis.isFromCategory(.spaces, c)) {
            try writer.writeByte(' ');
            continue;
        }

        // TODO(Corendos): From RFC 8265 Section 4.2.2:
        //                 4. Unicode Normalization Form C (NFC) MUST be applied to all strings.

        try writer.writeByte(c);
    }
}

/// This object is a stream that computes the MD5 checksum of what is written to it.
pub const Md5Stream = struct {
    state: std.crypto.hash.Md5 = std.crypto.hash.Md5.init(.{}),

    pub const Context = struct {
        state: *std.crypto.hash.Md5,
    };

    pub const Writer = std.io.Writer(Context, error{}, write);

    pub fn init() Md5Stream {
        return Md5Stream{ .state = std.crypto.hash.Md5.init(.{}) };
    }

    fn write(context: Context, bytes: []const u8) error{}!usize {
        context.state.update(bytes);
        return bytes.len;
    }

    pub fn writer(self: *Md5Stream) Writer {
        return Writer{ .context = .{ .state = &self.state } };
    }
};

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
    @memcpy(buffer[0..str.len], str);
    var stream = std.io.fixedBufferStream(&buffer);

    var output_buffer: [str.len]u8 = undefined;
    try readNoEofAligned(stream.reader(), 4, &output_buffer);
    const pos = try stream.getPos();

    try std.testing.expectEqual(@as(usize, 16), pos);
    try std.testing.expectEqualSlices(u8, str, &output_buffer);
}

test "OpaqueString smoke test" {
    const source = "This is a test";
    var storage: [128]u8 = undefined;
    const output = try computeOpaqueString(source, &storage);
    try std.testing.expectEqualSlices(u8, "This is a test", output);
}
