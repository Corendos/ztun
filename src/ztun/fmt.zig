// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("../ztun.zig");

/// Implementation of the `SliceHexSpacedFormatter` formatter.
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

/// Formats the given bytes as a space separated list of hexadecimal values.
pub const SliceHexSpacedFormatter = std.fmt.Formatter(formatSliceHexSpacedImpl);

/// Creates a `SliceHexSpacedFormatter` from the given source.
pub fn formatSliceHexSpaced(bytes: []const u8) SliceHexSpacedFormatter {
    return .{ .data = bytes };
}

test "format slice as hex" {
    const input = [_]u8{ 0x01, 0x02, 0x03 };
    try std.testing.expectFmt("0x01 0x02 0x03", "{}", .{formatSliceHexSpaced(&input)});
}

/// Implementation of the `StringSafeFormatter` formatter.
pub fn formatStringSafeImpl(bytes: []const u8, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = options;
    _ = fmt;
    for (bytes) |c| {
        if (std.ascii.isPrint(c)) {
            try writer.writeByte(c);
        } else {
            try writer.print("\\x{x:0>2}", .{c});
        }
    }
}

/// Formats the given bytes as an escaped ascii string.
pub const StringSafeFormatter = std.fmt.Formatter(formatStringSafeImpl);

/// Creates a `StringSafeFormatter` from the given source.
pub fn stringSafeFormatter(source: []const u8) StringSafeFormatter {
    return .{ .data = source };
}

test "format string safely" {
    const input = "string\xff";
    try std.testing.expectFmt("string\\xff", "{}", .{stringSafeFormatter(input)});
}

fn writeMessageHeader(message: ztun.Message, indentation: usize, writer: anytype) !void {
    try writer.writeByteNTimes(' ', indentation);
    try writer.writeAll("Message\n");
    try writer.writeByteNTimes(' ', indentation + 4);
    try writer.print("Class:          {s}\n", .{@tagName(message.type.class)});
    try writer.writeByteNTimes(' ', indentation + 4);
    try writer.print("Method:         {s}\n", .{@tagName(message.type.method)});
    try writer.writeByteNTimes(' ', indentation + 4);
    try writer.print("Transaction ID: {x}\n", .{message.transaction_id});
    try writer.writeByteNTimes(' ', indentation + 4);
    try writer.writeAll("Attributes:\n");
}

fn writeUnknownAttribute(attribute: ztun.Attribute, indentation: usize, writer: anytype) !void {
    try writer.writeByteNTimes(' ', indentation);
    try writer.print("Type: 0x{x:0>4}\n", .{attribute.type});
    try writer.writeByteNTimes(' ', indentation);
    try writer.print("Data: {any}\n", .{attribute.data});
}

fn toTypedAttributeOrWriteError(comptime T: type, attribute: ztun.Attribute, writer: anytype) !?T {
    return T.fromAttribute(attribute) catch blk: {
        try writer.writeAll("## ERROR ##\n");
        break :blk null;
    };
}

fn toTypedAttributeAllocOrWriteError(comptime T: type, attribute: ztun.Attribute, allocator: std.mem.Allocator, writer: anytype) !?T {
    return T.fromAttribute(attribute, allocator) catch blk: {
        try writer.writeAll("## ERROR ##\n");
        break :blk null;
    };
}

/// Implementation of `MessageFormatter` formatter.
pub fn formatMessageImpl(message: ztun.Message, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = options;
    if (std.mem.eql(u8, fmt, "inline")) {
        try writer.print("{any}", .{message});
    } else {
        try writeMessageHeader(message, 0, writer);
        for (message.attributes) |attribute, i| {
            try writer.writeByteNTimes(' ', 8);
            try writer.print("[{: >2}]:\n", .{i});
            switch (attribute.type) {
                @as(u16, ztun.attr.Type.mapped_address) => {
                    const mapped_address_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.MappedAddress, attribute, writer) orelse continue;
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type: MAPPED-ADDRESS\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("IP:   {}\n", .{mapped_address_attribute.family});
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Port: {}\n", .{mapped_address_attribute.port});
                },
                @as(u16, ztun.attr.Type.xor_mapped_address) => {
                    const xor_mapped_address_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.XorMappedAddress, attribute, writer) orelse continue;
                    const mapped_address_attribute = ztun.attr.common.decode(xor_mapped_address_attribute, message.transaction_id);
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:   XOR-MAPPED-ADDRESS\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("X-IP:   {} (decoded: {})\n", .{ xor_mapped_address_attribute.x_family, mapped_address_attribute.family });
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("X-Port: {} (decoded: {})\n", .{ xor_mapped_address_attribute.x_port, mapped_address_attribute.port });
                },
                @as(u16, ztun.attr.Type.username) => {
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  USERNAME\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Value: {s}\n", .{attribute.data});
                },
                @as(u16, ztun.attr.Type.userhash) => {
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  USERHASH\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Value: {s}\n", .{std.fmt.fmtSliceHexLower(attribute.data)});
                },
                @as(u16, ztun.attr.Type.message_integrity) => {
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  MESSAGE-INTEGRITY\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Value: {s}\n", .{std.fmt.fmtSliceHexLower(attribute.data)});
                },
                @as(u16, ztun.attr.Type.message_integrity_sha256) => {
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  MESSAGE-INTEGRITY-SHA256\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Value: {s}\n", .{std.fmt.fmtSliceHexLower(attribute.data)});
                },
                @as(u16, ztun.attr.Type.fingerprint) => {
                    const fingerprint_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.Fingerprint, attribute, writer) orelse continue;
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  FINGERPRINT\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Value: 0x{x:0>8}\n", .{fingerprint_attribute.value});
                },
                @as(u16, ztun.attr.Type.error_code) => {
                    const error_code_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.ErrorCode, attribute, writer) orelse continue;
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:   ERROR-CODE\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Code:   {}{:0>2} {s}\n", .{ error_code_attribute.value.class(), error_code_attribute.value.number(), @tagName(error_code_attribute.value) });
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Reason: {s}\n", .{error_code_attribute.reason});
                },
                @as(u16, ztun.attr.Type.realm) => {
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  REALM\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Value: {s}\n", .{attribute.data});
                },
                @as(u16, ztun.attr.Type.nonce) => {
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  NONCE\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Value: {s}\n", .{std.fmt.fmtSliceHexLower(attribute.data)});
                },
                @as(u16, ztun.attr.Type.password_algorithms) => {
                    var buffer: [128]u8 = undefined;
                    var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
                    const password_algorithms_attribute = try toTypedAttributeAllocOrWriteError(ztun.attr.common.PasswordAlgorithms, attribute, allocator_state.allocator(), writer) orelse continue;
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  PASSWORD-ALGORITHMS\n");
                    for (password_algorithms_attribute.algorithms) |algorithm, j| {
                        try writer.writeByteNTimes(' ', 20);
                        try writer.print("[{: >2}]:\n", .{j});
                        try writer.writeByteNTimes(' ', 24);
                        try writer.writeAll("Algorithm: ");
                        switch (algorithm.type) {
                            @as(u16, ztun.attr.common.AlgorithmType.md5) => try writer.writeAll("md5\n"),
                            @as(u16, ztun.attr.common.AlgorithmType.sha256) => try writer.writeAll("sha256\n"),
                            else => try writer.print("0x{x:0>4}\n", .{algorithm.type}),
                        }
                        try writer.writeByteNTimes(' ', 24);
                        try writer.print("Parameters: {any}\n", .{algorithm.parameters});
                    }
                },
                @as(u16, ztun.attr.Type.password_algorithm) => {
                    const password_algorithm_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.PasswordAlgorithm, attribute, writer) orelse continue;
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:       PASSWORD-ALGORITHM\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Algorithm:  ");
                    switch (password_algorithm_attribute.algorithm.type) {
                        @as(u16, ztun.attr.common.AlgorithmType.md5) => try writer.writeAll("md5\n"),
                        @as(u16, ztun.attr.common.AlgorithmType.sha256) => try writer.writeAll("sha256\n"),
                        else => try writer.print("0x{x:0>4}\n", .{password_algorithm_attribute.algorithm.type}),
                    }
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Parameters: {any}\n", .{password_algorithm_attribute.algorithm.parameters});
                },
                @as(u16, ztun.attr.Type.unknown_attributes) => {
                    var buffer: [128]u8 = undefined;
                    var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
                    const unknown_attributes_attribute = try toTypedAttributeAllocOrWriteError(ztun.attr.common.UnknownAttributes, attribute, allocator_state.allocator(), writer) orelse continue;
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type: UNKNOWN-ATTRIBUTES\n");
                    for (unknown_attributes_attribute.attribute_types) |a, j| {
                        try writer.writeByteNTimes(' ', 20);
                        try writer.print("[{: >2}]: 0x{x:0>4}\n", .{ j, a });
                    }
                },
                @as(u16, ztun.attr.Type.software) => {
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  SOFTWARE\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Value: {s}\n", .{attribute.data});
                },
                @as(u16, ztun.attr.Type.alternate_server) => {
                    const alternate_server_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.AlternateServer, attribute, writer) orelse continue;
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type: ALTERNATE-SERVER\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("IP:   {}\n", .{alternate_server_attribute.family});
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Port: {}\n", .{alternate_server_attribute.port});
                },
                @as(u16, ztun.attr.Type.alternate_domain) => {
                    try writer.writeByteNTimes(' ', 16);
                    try writer.writeAll("Type:  ALTERNATE-DOMAIN\n");
                    try writer.writeByteNTimes(' ', 16);
                    try writer.print("Value: {s}\n", .{attribute.data});
                },
                else => {
                    try writeUnknownAttribute(attribute, 16, writer);
                },
            }
        }
    }
}

/// Formats a ztun message.
/// There are two formating options:
/// * "inline" will produce the default Zig formatting of the message struct.
/// * <empty> will produce a human-friendly representation of the message.
pub const MessageFormatter = std.fmt.Formatter(formatMessageImpl);

/// Creates a `MessageFormatter` to format a STUN message.
pub fn messageFormatter(message: ztun.Message) MessageFormatter {
    return .{ .data = message };
}
