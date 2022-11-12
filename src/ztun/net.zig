// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const AddressType = enum {
    ipv4,
    ipv6,
};

pub const Ipv4Address = struct {
    value: u32,
    port: u16,

    pub fn parse(buf: []const u8, port: u16) !Ipv4Address {
        var result = Ipv4Address{
            .value = undefined,
            .port = port,
        };
        var out_ptr = [_]u8{ 0, 0, 0, 0 };
        var x: u8 = 0;
        var index: u8 = 0;
        var saw_any_digits = false;
        var has_zero_prefix = false;
        for (buf) |c| {
            if (c == '.') {
                if (!saw_any_digits) {
                    return error.InvalidCharacter;
                }
                if (index == 3) {
                    return error.InvalidEnd;
                }
                out_ptr[index] = x;
                index += 1;
                x = 0;
                saw_any_digits = false;
                has_zero_prefix = false;
            } else if (c >= '0' and c <= '9') {
                if (c == '0' and !saw_any_digits) {
                    has_zero_prefix = true;
                } else if (has_zero_prefix) {
                    return error.NonCanonical;
                }
                saw_any_digits = true;
                x = try std.math.mul(u8, x, 10);
                x = try std.math.add(u8, x, c - '0');
            } else {
                return error.InvalidCharacter;
            }
        }
        if (index == 3 and saw_any_digits) {
            out_ptr[index] = x;
            result.value = std.mem.bigToNative(u32, @bitCast(u32, out_ptr));
            return result;
        }

        return error.Incomplete;
    }

    pub fn format(self: Ipv4Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        const raw = @bitCast([4]u8, std.mem.nativeToBig(u32, self.value));
        try writer.print("{}.{}.{}.{}:{}", .{ raw[0], raw[1], raw[2], raw[3], self.port });
    }
};

pub const Ipv6Address = struct {
    value: u128,
    port: u16,

    pub fn format(self: Ipv6Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = writer;
        _ = self;
        _ = options;
        _ = fmt;
    }
};

pub const Address = union(enum) {
    ipv4: Ipv4Address,
    ipv6: Ipv6Address,

    pub fn format(self: Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        return switch (self) {
            inline else => |address| address.format(fmt, options, writer),
        };
    }
};

test "parse IPv4" {
    const address = try Ipv4Address.parse("127.0.0.1", 8888);
    try std.testing.expectEqual(@as(u32, 0x7F000001), address.value);
    try std.testing.expectEqual(@as(u16, 8888), address.port);
}
