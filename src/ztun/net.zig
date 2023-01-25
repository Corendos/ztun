// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

// NOTE: This code is greatly inspired/copied from the Zig std lib.

/// Represents an IP address type.
pub const AddressType = enum {
    ipv4,
    ipv6,
};

/// Represents an IPv4 address.
pub const Ipv4Address = struct {
    value: u32,
    port: u16,

    /// Tries to parse an IPv4 address from the given string and with the given.
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

/// Represents an IPv6 address.
pub const Ipv6Address = struct {
    value: u128,
    port: u16,
    flowinfo: u32 = 0,
    scope_id: u32 = 0,

    /// Tries to parse an IPv4 address from the given string and with the given.
    pub fn parse(buf: []const u8, port: u16) !Ipv6Address {
        var result = Ipv6Address{
            .value = undefined,
            .port = port,
            .flowinfo = 0,
            .scope_id = 0,
        };
        var output: [16]u8 = undefined;
        var ip_slice = output[0..];

        var tail: [16]u8 = undefined;

        var x: u16 = 0;
        var saw_any_digits = false;
        var index: u8 = 0;
        var scope_id = false;
        var abbrv = false;
        for (buf) |c, i| {
            if (scope_id) {
                if (c >= '0' and c <= '9') {
                    const digit = c - '0';
                    {
                        const ov = @mulWithOverflow(result.scope_id, 10);
                        if (ov[1] != 0) return error.Overflow;
                        result.scope_id = ov[0];
                    }
                    {
                        const ov = @addWithOverflow(result.scope_id, digit);
                        if (ov[1] != 0) return error.Overflow;
                        result.scope_id = ov[0];
                    }
                } else {
                    return error.InvalidCharacter;
                }
            } else if (c == ':') {
                if (!saw_any_digits) {
                    if (abbrv) return error.InvalidCharacter; // ':::'
                    if (i != 0) abbrv = true;
                    std.mem.set(u8, ip_slice[index..], 0);
                    ip_slice = tail[0..];
                    index = 0;
                    continue;
                }
                if (index == 14) {
                    return error.InvalidEnd;
                }
                ip_slice[index] = @truncate(u8, x >> 8);
                index += 1;
                ip_slice[index] = @truncate(u8, x);
                index += 1;

                x = 0;
                saw_any_digits = false;
            } else if (c == '%') {
                if (!saw_any_digits) {
                    return error.InvalidCharacter;
                }
                scope_id = true;
                saw_any_digits = false;
            } else if (c == '.') {
                if (!abbrv or ip_slice[0] != 0xff or ip_slice[1] != 0xff) {
                    // must start with '::ffff:'
                    return error.InvalidIpv4Mapping;
                }
                const start_index = std.mem.lastIndexOfScalar(u8, buf[0..i], ':').? + 1;
                const addr = (Ipv4Address.parse(buf[start_index..], 0) catch {
                    return error.InvalidIpv4Mapping;
                }).value;
                ip_slice = output[0..];
                ip_slice[10] = 0xff;
                ip_slice[11] = 0xff;

                const ptr = std.mem.sliceAsBytes(@as(*const [1]u32, &addr)[0..]);

                ip_slice[12] = ptr[0];
                ip_slice[13] = ptr[1];
                ip_slice[14] = ptr[2];
                ip_slice[15] = ptr[3];
                return result;
            } else {
                const digit = try std.fmt.charToDigit(c, 16);
                {
                    const ov = @mulWithOverflow(x, 16);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                {
                    const ov = @addWithOverflow(x, digit);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                saw_any_digits = true;
            }
        }

        if (!saw_any_digits and !abbrv) {
            return error.Incomplete;
        }

        if (index == 14) {
            ip_slice[14] = @truncate(u8, x >> 8);
            ip_slice[15] = @truncate(u8, x);
        } else {
            ip_slice[index] = @truncate(u8, x >> 8);
            index += 1;
            ip_slice[index] = @truncate(u8, x);
            index += 1;
            std.mem.copy(u8, output[16 - index ..], ip_slice[0..index]);
        }
        result.value = std.mem.bigToNative(u128, @bitCast(u128, output));
        return result;
    }

    pub fn format(self: Ipv6Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        const raw = @bitCast([16]u8, std.mem.nativeToBig(u128, self.value));
        try writer.print("[{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            raw[0],
            raw[1],
            raw[2],
            raw[3],
            raw[4],
            raw[5],
            raw[6],
            raw[7],
            raw[8],
            raw[9],
            raw[10],
            raw[11],
            raw[12],
            raw[13],
            raw[14],
            raw[15],
        });
        if (self.scope_id != 0) {
            try writer.print("%{}", .{self.scope_id});
        }
        try writer.print("]:{}", .{self.port});
    }
};

/// Represents an IP address that can be IPv4 or IPv6.
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

test "parse IPv6" {
    {
        const address = try Ipv6Address.parse("7ef::1%32", 8888);
        try std.testing.expectEqual(@as(u128, 0x07ef_0000_0000_0000_0000_0000_0000_0001), address.value);
        try std.testing.expectEqual(@as(u16, 8888), address.port);
        try std.testing.expectEqual(@as(u32, 32), address.scope_id);
    }
    {
        const address = try Ipv6Address.parse("::1", 8888);
        try std.testing.expectEqual(@as(u128, 0x0000_0000_0000_0000_0000_0000_0000_0001), address.value);
        try std.testing.expectEqual(@as(u16, 8888), address.port);
        try std.testing.expectEqual(@as(u32, 0), address.scope_id);
    }
}
