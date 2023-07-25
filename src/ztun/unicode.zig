const std = @import("std");

pub const tables = @import("unicode/tables.zig");

// WARN(Corendos): This is a WIP
//
// This is supposed to implement the computation required to build an OpaqueString as specified in RFC 8265 (https://www.rfc-editor.org/rfc/rfc8265).
// It's a work in progress as it relies on a lot of other things being defined.
//

inline fn between(min: u21, max: u21, c: u21) bool {
    return min <= c and c <= max;
}

const unicode = @This();

pub const Category = enum {
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
    unassigned,
};

pub fn isFromCategory(comptime category: Category, c: u21) bool {
    @setEvalBranchQuota(4000);
    inline for (tables.category_table) |candidate| {
        if (candidate.category == category and between(candidate.start, candidate.end, c)) return true;
    }
    return false;
}

pub fn isFromCategories(comptime categories: []const Category, c: u21) bool {
    inline for (categories) |category| {
        if (isFromCategory(category, c)) return true;
    }
    return false;
}

pub const precis = struct {
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

    pub inline fn isFromCategory(comptime category: precis.Category, c: u21) bool {
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

    pub fn isFromCategories(comptime categories: []const precis.Category, c: u21) bool {
        inline for (categories) |category| {
            if (precis.isFromCategory(category, c)) return true;
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

test "freeform ascii smoke test" {
    try std.testing.expect(isFreeFormAsciiString("test"));
    try std.testing.expect(isFreeFormAsciiString("another test"));
    try std.testing.expect(isFreeFormAsciiString("another:test"));
}
