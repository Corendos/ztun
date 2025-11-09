// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const unicode = @import("unicode.zig");

/// Writes the input bytes to the writer and pad with 0 to align the amount written to the given alignment.
pub fn writeAllAligned(bytes: []const u8, alignment: usize, writer: *std.Io.Writer) !void {
    try writer.writeAll(bytes);
    const padding = std.mem.alignForward(usize, bytes.len, alignment) - bytes.len;
    try writer.splatByteAll(0, padding);
}

/// Reads enough bytes to fill the buffer (or fail with an error on EOF) and skip bytes to align the amount read
/// to the given alignment.
pub fn readNoEofAligned(reader: *std.Io.Reader, alignment: usize, buf: []u8) !void {
    try reader.readSliceAll(buf);
    const padding = std.mem.alignForward(u64, buf.len, alignment) - buf.len;
    try reader.discardAll(padding);
}

pub const WriteOpaqueStringError = error{InvalidString} || std.Io.Writer.Error;

/// Writes the OpaqueString produced by the given source to the writer.
pub fn writeOpaqueString(source: []const u8, writer: *std.Io.Writer) WriteOpaqueStringError!void {
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

/// This object is a writer that computes the MD5 checksum of what is written to it.
pub const Md5Writer = std.Io.Writer.Hashing(std.crypto.hash.Md5);

/// This object is a writer that computes the SHA256 checksum of what is written to it.
pub const Sha256Writer = std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256);

test "write all aligned" {
    const str = [_]u8{ 1, 2, 3 };
    var buffer: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeAllAligned(&str, 4, &writer);
    const written = writer.buffered();
    try std.testing.expectEqual(@as(usize, 4), written.len);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 0 }, written);
}

test "read all aligned" {
    var buffer = [_]u8{0} ** 128;
    const str = "This is a test";
    @memcpy(buffer[0..str.len], str);
    var reader = std.Io.Reader.fixed(&buffer);

    var output_buffer: [str.len]u8 = undefined;
    try readNoEofAligned(&reader, 4, &output_buffer);

    try std.testing.expectEqual(@as(usize, 16), reader.seek);
    try std.testing.expectEqualSlices(u8, str, &output_buffer);
}

test "OpaqueString smoke test" {
    const source = "This is a test";
    var storage: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    try writeOpaqueString(source, &writer);
    try std.testing.expectEqualSlices(u8, "This is a test", writer.buffered());
}
