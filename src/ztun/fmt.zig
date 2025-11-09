// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const ztun = @import("../ztun.zig");

/// Formats the given bytes as a space separated list of hexadecimal values.
pub const SliceHexSpacedFormatter = struct {
    data: []const u8,

    pub fn format(self: SliceHexSpacedFormatter, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const charset = "0123456789ABCDEF";
        var buf: [4]u8 = undefined;

        buf[0] = '0';
        buf[1] = 'x';

        for (self.data, 0..) |c, i| {
            if (i > 0) {
                try writer.writeByte(' ');
            }
            buf[2] = charset[c >> 4];
            buf[3] = charset[c & 15];
            try writer.writeAll(&buf);
        }
    }
};

/// Creates a `SliceHexSpacedFormatter` from the given source.
pub fn formatSliceHexSpaced(bytes: []const u8) SliceHexSpacedFormatter {
    return .{ .data = bytes };
}

test "format slice as hex" {
    const input = [_]u8{ 0x01, 0x02, 0x03 };
    try std.testing.expectFmt("0x01 0x02 0x03", "{f}", .{formatSliceHexSpaced(&input)});
}

/// Implementation of the `StringSafeFormatter` formatter.
/// Formats the given bytes as an escaped ascii string.
pub const StringSafeFormatter = struct {
    data: []const u8,

    pub fn format(self: StringSafeFormatter, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.data) |c| {
            if (std.ascii.isPrint(c)) {
                try writer.writeByte(c);
            } else {
                try writer.print("\\x{x:0>2}", .{c});
            }
        }
    }
};

/// Creates a `StringSafeFormatter` from the given source.
pub fn stringSafeFormatter(source: []const u8) StringSafeFormatter {
    return .{ .data = source };
}

test "format string safely" {
    const input = "string\xff";
    try std.testing.expectFmt("string\\xff", "{f}", .{stringSafeFormatter(input)});
}

fn writeMessageHeader(message: ztun.Message, indentation: usize, writer: *std.Io.Writer) !void {
    try writer.splatByteAll(' ', indentation);
    try writer.writeAll("Message\n");
    try writer.splatByteAll(' ', indentation + 4);
    try writer.print("Class:          {s}\n", .{@tagName(message.type.class)});
    try writer.splatByteAll(' ', indentation + 4);
    try writer.print("Method:         {s}\n", .{@tagName(message.type.method)});
    try writer.splatByteAll(' ', indentation + 4);
    try writer.print("Transaction ID: {x:0>24}\n", .{message.transaction_id});
    try writer.splatByteAll(' ', indentation + 4);
    try writer.writeAll("Attributes:\n");
}

fn writeUnknownAttribute(attribute: ztun.Attribute, indentation: usize, writer: *std.Io.Writer) !void {
    try writer.splatByteAll(' ', indentation);
    try writer.print("Type: 0x{x:0>4}\n", .{attribute.type});
    try writer.splatByteAll(' ', indentation);
    try writer.print("Data: {any}\n", .{attribute.data});
}

fn toTypedAttributeOrWriteError(comptime T: type, attribute: ztun.Attribute, writer: *std.Io.Writer) !?T {
    return T.fromAttribute(attribute) catch blk: {
        try writer.writeAll("## ERROR ##\n");
        break :blk null;
    };
}

fn toTypedAttributeAllocOrWriteError(comptime T: type, attribute: ztun.Attribute, allocator: std.mem.Allocator, writer: *std.Io.Writer) !?T {
    return T.fromAttribute(attribute, allocator) catch blk: {
        try writer.writeAll("## ERROR ##\n");
        break :blk null;
    };
}

pub fn formatMessageImpl(message: ztun.Message, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writeMessageHeader(message, 0, writer);
    for (message.attributes, 0..) |attribute, i| {
        try writer.splatByteAll(' ', 8);
        try writer.print("[{: >2}]:\n", .{i});
        switch (attribute.type) {
            @as(u16, ztun.attr.Type.mapped_address) => {
                const mapped_address_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.MappedAddress, attribute, writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type: MAPPED-ADDRESS\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("IP:   {f}\n", .{mapped_address_attribute.family});
                try writer.splatByteAll(' ', 16);
                try writer.print("Port: {}\n", .{mapped_address_attribute.port});
            },
            @as(u16, ztun.attr.Type.xor_mapped_address) => {
                const xor_mapped_address_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.XorMappedAddress, attribute, writer) orelse continue;
                const mapped_address_attribute = ztun.attr.common.decode(xor_mapped_address_attribute, message.transaction_id);
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:   XOR-MAPPED-ADDRESS\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("X-IP:   {f} (decoded: {f})\n", .{ xor_mapped_address_attribute.x_family, mapped_address_attribute.family });
                try writer.splatByteAll(' ', 16);
                try writer.print("X-Port: {} (decoded: {})\n", .{ xor_mapped_address_attribute.x_port, mapped_address_attribute.port });
            },
            @as(u16, ztun.attr.Type.username) => {
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  USERNAME\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: {s}\n", .{attribute.data});
            },
            @as(u16, ztun.attr.Type.userhash) => {
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  USERHASH\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: {x}\n", .{attribute.data});
            },
            @as(u16, ztun.attr.Type.message_integrity) => {
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  MESSAGE-INTEGRITY\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: {x}\n", .{attribute.data});
            },
            @as(u16, ztun.attr.Type.message_integrity_sha256) => {
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  MESSAGE-INTEGRITY-SHA256\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: {x}\n", .{attribute.data});
            },
            @as(u16, ztun.attr.Type.fingerprint) => {
                const fingerprint_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.Fingerprint, attribute, writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  FINGERPRINT\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: 0x{x:0>8}\n", .{fingerprint_attribute.value});
            },
            @as(u16, ztun.attr.Type.error_code) => {
                const error_code_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.ErrorCode, attribute, writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:   ERROR-CODE\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Code:   {}{:0>2} {s}\n", .{ error_code_attribute.value.class(), error_code_attribute.value.number(), @tagName(error_code_attribute.value) });
                try writer.splatByteAll(' ', 16);
                try writer.print("Reason: {s}\n", .{error_code_attribute.reason});
            },
            @as(u16, ztun.attr.Type.realm) => {
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  REALM\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: {s}\n", .{attribute.data});
            },
            @as(u16, ztun.attr.Type.nonce) => {
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  NONCE\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: {x}\n", .{attribute.data});
            },
            @as(u16, ztun.attr.Type.password_algorithms) => {
                var buffer: [128]u8 = undefined;
                var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
                const password_algorithms_attribute = try toTypedAttributeAllocOrWriteError(ztun.attr.common.PasswordAlgorithms, attribute, allocator_state.allocator(), writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  PASSWORD-ALGORITHMS\n");
                for (password_algorithms_attribute.algorithms, 0..) |algorithm, j| {
                    try writer.splatByteAll(' ', 20);
                    try writer.print("[{: >2}]:\n", .{j});
                    try writer.splatByteAll(' ', 24);
                    try writer.writeAll("Algorithm: ");
                    switch (algorithm.type) {
                        .md5 => try writer.writeAll("md5\n"),
                        .sha256 => try writer.writeAll("sha256\n"),
                        _ => try writer.print("0x{x:0>4}\n", .{algorithm.type}),
                    }
                    try writer.splatByteAll(' ', 24);
                    try writer.print("Parameters: {any}\n", .{algorithm.parameters});
                }
            },
            @as(u16, ztun.attr.Type.password_algorithm) => {
                const password_algorithm_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.PasswordAlgorithm, attribute, writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:       PASSWORD-ALGORITHM\n");
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Algorithm:  ");
                switch (password_algorithm_attribute.algorithm.type) {
                    .md5 => try writer.writeAll("md5\n"),
                    .sha256 => try writer.writeAll("sha256\n"),
                    _ => try writer.print("0x{x:0>4}\n", .{password_algorithm_attribute.algorithm.type}),
                }
                try writer.splatByteAll(' ', 16);
                try writer.print("Parameters: {any}\n", .{password_algorithm_attribute.algorithm.parameters});
            },
            @as(u16, ztun.attr.Type.unknown_attributes) => {
                var buffer: [128]u8 = undefined;
                var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
                const unknown_attributes_attribute = try toTypedAttributeAllocOrWriteError(ztun.attr.common.UnknownAttributes, attribute, allocator_state.allocator(), writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type: UNKNOWN-ATTRIBUTES\n");
                for (unknown_attributes_attribute.attribute_types, 0..) |a, j| {
                    try writer.splatByteAll(' ', 20);
                    try writer.print("[{: >2}]: 0x{x:0>4}\n", .{ j, a });
                }
            },
            @as(u16, ztun.attr.Type.software) => {
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  SOFTWARE\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: {s}\n", .{attribute.data});
            },
            @as(u16, ztun.attr.Type.alternate_server) => {
                const alternate_server_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.AlternateServer, attribute, writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type: ALTERNATE-SERVER\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("IP:   {f}\n", .{alternate_server_attribute.family});
                try writer.splatByteAll(' ', 16);
                try writer.print("Port: {}\n", .{alternate_server_attribute.port});
            },
            @as(u16, ztun.attr.Type.alternate_domain) => {
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  ALTERNATE-DOMAIN\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: {s}\n", .{attribute.data});
            },
            @as(u16, ztun.attr.Type.priority) => {
                const priority_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.Priority, attribute, writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  PRIORITY\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: 0x{x}\n", .{priority_attribute.value});
            },
            @as(u16, ztun.attr.Type.use_candidate) => {
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type: USE-CANDIDATE\n");
            },
            @as(u16, ztun.attr.Type.ice_controlled) => {
                const ice_controlled_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.IceControlled, attribute, writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  ICE-CONTROLLED\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: 0x{x}\n", .{ice_controlled_attribute.value});
            },
            @as(u16, ztun.attr.Type.ice_controlling) => {
                const ice_controlling_attribute = try toTypedAttributeOrWriteError(ztun.attr.common.IceControlling, attribute, writer) orelse continue;
                try writer.splatByteAll(' ', 16);
                try writer.writeAll("Type:  ICE-CONTROLLING\n");
                try writer.splatByteAll(' ', 16);
                try writer.print("Value: 0x{x}\n", .{ice_controlling_attribute.value});
            },
            else => {
                try writeUnknownAttribute(attribute, 16, writer);
            },
        }
    }
}
