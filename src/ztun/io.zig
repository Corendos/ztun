// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

/// Writes the input bytes to the writer and pad with 0 to align the amount written to the given alignment.
pub fn writeAllAligned(bytes: []const u8, alignment: usize, writer: anytype) !void {
    try writer.writeAll(bytes);
    const padding = std.mem.alignForward(bytes.len, alignment) - bytes.len;
    try writer.writeByteNTimes(0, padding);
}

/// Reads enough bytes to fill the buffer (or fail with an error on EOF) and skip bytes to align the amount read
/// to the given alignment.
pub fn readNoEofAligned(reader: anytype, alignment: usize, buf: []u8) !void {
    try reader.readNoEof(buf);
    const padding = std.mem.alignForward(buf.len, alignment) - buf.len;
    try reader.skipBytes(@as(u64, padding), .{ .buf_size = 16 });
}

//
// WARN(Corendos): This is a WIP
//
// This is supposed to implement the computation required to build an OpaqueString as specified in RFC 8265 (https://www.rfc-editor.org/rfc/rfc8265).
// It's a work in progress as it relies on a lot of other things being defined.
//

inline fn between(min: u21, max: u21, c: u21) bool {
    return min <= c and c <= max;
}

const unicode = struct {
    const Category = enum {
        control,
        format,
        private_use,
        surrogate,
        lowercase_letter,
        modifier_letter,
        other_letter,
        titlecase_letter,
        uppercase_letter,
        spacing_mark,
        enclosing_mark,
        nonspacing_mark,
        decimal_number,
        letter_number,
        other_number,
        connector_punctuation,
        dash_punctuation,
        close_punctuation,
        final_punctuation,
        initial_punctuation,
        other_punctuation,
        open_punctuation,
        currency_symbol,
        modifier_symbol,
        math_symbol,
        other_symbol,
        line_separator,
        paragraph_separator,
        space_separator,
    };

    pub fn isFromCategory(comptime category: Category, c: u21) bool {
        return switch (category) {
            .control => between(0x00, 0x1f, c) or between(0x7f, 0x9f, c),
            .format => c == 0xad or
                between(0x600, 0x605, c) or
                c == 0x61c or c == 0x6dd or c == 0x70f or c == 0x8e2 or c == 0x180e or
                between(0x200b, 0x200f, c) or
                between(0x202a, 0x202e, c) or
                (between(0x2060, 0x206f, c) and c != 0x2065) or
                c == 0xfeff or
                between(0xfff9, 0xfffb, c) or
                c == 0x110bd or c == 0x110cd or
                between(0x13430, 0x13438, c) or
                between(0x1bca0, 0x1bca3, c) or
                between(0x1d173, 0x1d17a, c) or
                c == 0xe0001 or
                between(0xe0020, 0xe007f, c),
            .private_use => false,
            .surrogate => false,
            .lowercase_letter => between(0x61, 0x7a, c),
            .modifier_letter => between(0x41, 0x5a, c),
            .other_letter => false,
            .titlecase_letter => false,
            .uppercase_letter => false,
            .spacing_mark => false,
            .enclosing_mark => false,
            .nonspacing_mark => false,
            .decimal_number => false,
            .letter_number => false,
            .other_number => false,
            .connector_punctuation => false,
            .dash_punctuation => false,
            .close_punctuation => false,
            .final_punctuation => false,
            .initial_punctuation => false,
            .other_punctuation => false,
            .open_punctuation => false,
            .currency_symbol => false,
            .modifier_symbol => false,
            .math_symbol => false,
            .other_symbol => false,
            .line_separator => c == 0x02028,
            .paragraph_separator => c == 0x2029,
            .space_separator => c == 0x20 or c == 0xa0 or c == 0x1680 or between(0x2000, 0x200a, c) or c == 0x202f or c == 0x205f or c == 0x3000,
        };
    }

    pub fn isFromCategories(comptime categories: []const Category, c: u21) bool {
        inline for (categories) |category| {
            if (isFromCategory(category, c)) return true;
        }
        return false;
    }
};

test "counting control characters" {
    var i: u21 = 0;
    var count: usize = 0;
    while (i < std.math.maxInt(u21)) : (i += 1) {
        if (unicode.isFromCategory(.format, i)) {
            count += 1;
        }
    }

    try std.testing.expectEqual(@as(usize, 161), count);
}

const precis = struct {
    pub const Category = enum {
        letter_digits,
        exceptions,
        backward_compatible,
        join_control,
        old_hangul_jamo,
        unassigned,
        ascii7,
        controls,
        precis_ignorable_properties,
        spaces,
        symbols,
        punctuation,
        has_compat,
        other_letter_digits,
    };

    pub inline fn isFromCategory(comptime category: Category, c: u21) bool {
        return switch (category) {
            .letter_digits => unicode.isFromCategories(&.{
                .lowercase_letter,
                .uppercase_letter,
                .other_letter,
                .decimal_number,
                .modifier_letter,
                .nonspacing_mark,
                .spacing_mark,
            }, c),
            .exceptions => c == 0x00B7 or c == 0x00DF or c == 0x0375 or c == 0x03C2 or
                c == 0x05F3 or c == 0x05F4 or c == 0x0640 or c == 0x0660 or c == 0x0661 or
                c == 0x0662 or c == 0x0663 or c == 0x0664 or c == 0x0665 or c == 0x0666 or
                c == 0x0667 or c == 0x0668 or c == 0x0669 or c == 0x06F0 or c == 0x06F1 or
                c == 0x06F2 or c == 0x06F3 or c == 0x06F4 or c == 0x06F5 or c == 0x06F6 or
                c == 0x06F7 or c == 0x06F8 or c == 0x06F9 or c == 0x06FD or c == 0x06FE or
                c == 0x07FA or c == 0x0F0B or c == 0x3007 or c == 0x302E or c == 0x302F or
                c == 0x3031 or c == 0x3032 or c == 0x3033 or c == 0x3034 or c == 0x3035 or
                c == 0x303B or c == 0x30FB,
            .backward_compatible => false,
            .join_control => false,
            .old_hangul_jamo => false,
            .unassigned => false,
            .ascii7 => false,
            .controls => unicode.isFromCategory(.control, c),
            .precis_ignorable_properties => false,
            .spaces => unicode.isFromCategory(.space_separator, c),
            .symbols => unicode.isFromCategories(&.{
                .math_symbol,
                .currency_symbol,
                .modifier_symbol,
                .other_symbol,
            }, c),
            .punctuation => unicode.isFromCategories(&.{
                .connector_punctuation,
                .dash_punctuation,
                .open_punctuation,
                .close_punctuation,
                .initial_punctuation,
                .final_punctuation,
                .other_punctuation,
            }, c),
            .has_compat => false,
            .other_letter_digits => unicode.isFromCategories(&.{
                .titlecase_letter, .letter_number, .other_number, .enclosing_mark,
            }, c),
        };
    }

    pub fn isFromCategories(comptime categories: []const Category, c: u21) bool {
        inline for (categories) |category| {
            if (isFromCategory(category, c)) return true;
        }
        return false;
    }
};

pub inline fn isFreeFormAscii(c: u8) bool {
    return precis.isFromCategories(&.{
        .letter_digits,
        .ascii7,
        .spaces,
        .symbols,
        .punctuation,
        .has_compat,
        .other_letter_digits,
    }, c);
}

pub fn isFreeFormAsciiString(source: []const u8) bool {
    for (source) |c| {
        if (!isFreeFormAscii(c)) return false;
    }

    return true;
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
    if (!isFreeFormAsciiString(source)) return error.InvalidString;
    for (source) |c| {
        // TODO(Corendos): From RFC 8265 Section 4.2.2:
        //                 1. Fullwidth and halfwidth code points MUST NOT be mapped to their decomposition mappings.
        if (precis.isFromCategory(.spaces, c)) {
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
    std.mem.copy(u8, &buffer, str);
    var stream = std.io.fixedBufferStream(&buffer);

    var output_buffer: [str.len]u8 = undefined;
    try readNoEofAligned(stream.reader(), 4, &output_buffer);
    const pos = try stream.getPos();

    try std.testing.expectEqual(@as(usize, 16), pos);
    try std.testing.expectEqualSlices(u8, str, &output_buffer);
}

test "freeform ascii smoke test" {
    try std.testing.expect(isFreeFormAsciiString("test"));
    try std.testing.expect(isFreeFormAsciiString("another test"));
}

test "OpaqueString smoke test" {
    const source = "This is a test";
    var storage: [128]u8 = undefined;
    const output = try computeOpaqueString(source, &storage);
    try std.testing.expectEqualSlices(u8, "This is a test", output);
}
