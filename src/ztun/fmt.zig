// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("../ztun.zig");

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

test "format slice as hex" {
    const input = [_]u8{ 0x01, 0x02, 0x03 };
    try std.testing.expectFmt("0x01 0x02 0x03", "{}", .{formatSliceHexSpaced(&input)});
}

pub fn messageFormatter(message: *const ztun.Message) MessageFormatter {
    return MessageFormatter{ .message = message };
}

pub const MessageFormatter = struct {
    message: *const ztun.Message,

    pub fn format(self: MessageFormatter, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        const message = self.message;

        if (std.mem.eql(u8, fmt, "inline")) {
            try writer.print("{any}", .{message});
        } else {
            const header_format =
                \\Message
                \\    Class:          {s}
                \\    Method:         {s}
                \\    Transaction ID: {x}
                \\    Attributes:
                \\
            ;

            const unknown_attribute_format =
                \\                Type: 0x{x:0>4}
                \\                Data: {any}
                \\
            ;
            try writer.print(header_format, .{ @tagName(message.type.class), @tagName(message.type.method), message.transaction_id });
            for (message.attributes) |attribute, i| {
                try writer.print("        [{: >3}]:\n", .{i});
                switch (attribute.type) {
                    @as(u16, ztun.attr.Type.mapped_address) => {
                        const mapped_address_attribute = ztun.attr.common.MappedAddress.fromAttribute(attribute) catch {
                            try writer.writeAll("##ERROR##\n");
                            continue;
                        };
                        try writer.print(
                            \\                Type: MAPPED-ADDRESS
                            \\                IP:   {}
                            \\                Port: {}
                            \\
                        , .{ mapped_address_attribute.family, mapped_address_attribute.port });
                    },
                    @as(u16, ztun.attr.Type.xor_mapped_address) => {
                        const xor_mapped_address_attribute = ztun.attr.common.XorMappedAddress.fromAttribute(attribute) catch {
                            try writer.writeAll("##ERROR##\n");
                            continue;
                        };
                        const mapped_address_attribute = ztun.attr.common.decode(xor_mapped_address_attribute, message.transaction_id);
                        try writer.print(
                            \\                Type:   XOR-MAPPED-ADDRESS
                            \\                X-IP:   {} (decoded: {})
                            \\                X-Port: {} (decoded: {})
                            \\
                        , .{ xor_mapped_address_attribute.x_family, mapped_address_attribute.family, xor_mapped_address_attribute.x_port, mapped_address_attribute.port });
                    },
                    @as(u16, ztun.attr.Type.username) => {
                        try writer.print(
                            \\                Type:  USERNAME
                            \\                Value: {s}
                            \\
                        , .{attribute.data});
                    },
                    @as(u16, ztun.attr.Type.userhash) => {
                        try writer.print(
                            \\                Type:  USERHASH
                            \\                Value: {s}
                            \\
                        , .{std.fmt.fmtSliceHexLower(attribute.data)});
                    },
                    @as(u16, ztun.attr.Type.message_integrity) => {
                        try writer.print(
                            \\                Type:  MESSAGE-INTEGRITY
                            \\                Value: {s}
                            \\
                        , .{std.fmt.fmtSliceHexLower(attribute.data)});
                    },
                    @as(u16, ztun.attr.Type.message_integrity_sha256) => {
                        try writer.print(
                            \\                Type:  MESSAGE-INTEGRITY-SHA256
                            \\                Value: {s}
                            \\
                        , .{std.fmt.fmtSliceHexLower(attribute.data)});
                    },
                    @as(u16, ztun.attr.Type.fingerprint) => {
                        const fingerprint_attribute = ztun.attr.common.Fingerprint.fromAttribute(attribute) catch {
                            try writer.writeAll("##ERROR##\n");
                            continue;
                        };
                        try writer.print(
                            \\                Type:  FINGERPRINT
                            \\                Value: 0x{x:8>0}
                            \\
                        , .{fingerprint_attribute.value});
                    },
                    @as(u16, ztun.attr.Type.error_code) => {
                        const error_code_attribute = ztun.attr.common.ErrorCode.fromAttribute(attribute) catch {
                            try writer.writeAll("##ERROR##\n");
                            continue;
                        };
                        try writer.print(
                            \\                Type:   ERROR-CODE
                            \\                Code:   {}{:0>2} {s}
                            \\                Reason: {s}
                            \\
                        , .{ error_code_attribute.value.class(), error_code_attribute.value.number(), @tagName(error_code_attribute.value), error_code_attribute.reason });
                    },
                    @as(u16, ztun.attr.Type.realm) => {
                        try writer.print(
                            \\                Type: REALM
                            \\                Value: {s}
                            \\
                        , .{attribute.data});
                    },
                    @as(u16, ztun.attr.Type.nonce) => {
                        try writer.print(
                            \\                Type: NONCE
                            \\                Value: {s}
                            \\
                        , .{std.fmt.fmtSliceHexLower(attribute.data)});
                    },
                    @as(u16, ztun.attr.Type.password_algorithms) => {
                        var buffer: [128]u8 = undefined;
                        var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
                        const password_algorithms_attribute = ztun.attr.common.PasswordAlgorithms.fromAttribute(attribute, allocator_state.allocator()) catch {
                            try writer.writeAll("##ERROR##\n");
                            continue;
                        };
                        try writer.writeAll("                Type: PASSWORD-ALGORITHMS\n");
                        for (password_algorithms_attribute.algorithms) |algorithm, j| {
                            try writer.print("                    [{: >2}]:\n", .{j});
                            switch (algorithm.type) {
                                @as(u16, ztun.attr.common.AlgorithmType.md5) => try writer.writeAll("                        Algorithm: md5\n"),
                                @as(u16, ztun.attr.common.AlgorithmType.sha256) => try writer.writeAll("                        Algorithm: sha256\n"),
                                else => try writer.print("                        Algorithm: 0x{x:0>4}\n", .{algorithm.type}),
                            }
                            try writer.print("                        Parameters: {any}\n", .{algorithm.parameters});
                        }
                    },
                    @as(u16, ztun.attr.Type.password_algorithm) => {
                        const password_algorithm_attribute = ztun.attr.common.PasswordAlgorithm.fromAttribute(attribute) catch {
                            try writer.writeAll("##ERROR##\n");
                            continue;
                        };
                        try writer.writeAll("                Type: PASSWORD-ALGORITHM\n");
                        switch (password_algorithm_attribute.algorithm.type) {
                            @as(u16, ztun.attr.common.AlgorithmType.md5) => try writer.writeAll("                    Algorithm: md5\n"),
                            @as(u16, ztun.attr.common.AlgorithmType.sha256) => try writer.writeAll("                    Algorithm: sha256\n"),
                            else => try writer.print("                    Algorithm: 0x{x:0>4}\n", .{password_algorithm_attribute.algorithm.type}),
                        }
                        try writer.print("                    Parameters: {any}\n", .{password_algorithm_attribute.algorithm.parameters});
                    },
                    @as(u16, ztun.attr.Type.unknown_attributes) => {
                        var buffer: [128]u8 = undefined;
                        var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
                        const unknown_attributes_attribute = ztun.attr.common.UnknownAttributes.fromAttribute(attribute, allocator_state.allocator()) catch {
                            try writer.writeAll("##ERROR##\n");
                            continue;
                        };

                        try writer.writeAll("                Type: UNKNOWN-ATTRIBUTES\n");
                        for (unknown_attributes_attribute.attribute_types) |a, j| {
                            try writer.print("                    [{: >2}]: 0x{x:0>4}\n", .{ j, a });
                        }
                    },
                    @as(u16, ztun.attr.Type.software) => {
                        try writer.print(
                            \\                Type: SOFTWARE
                            \\                Value: {s}
                            \\
                        , .{attribute.data});
                    },
                    @as(u16, ztun.attr.Type.alternate_server) => {
                        const alternate_server_attribute = ztun.attr.common.AlternateServer.fromAttribute(attribute) catch {
                            try writer.writeAll("##ERROR##\n");
                            continue;
                        };
                        try writer.print(
                            \\                Type: ALTERNATE-SERVER
                            \\                IP:   {}
                            \\                Port: {}
                            \\
                        , .{ alternate_server_attribute.family, alternate_server_attribute.port });
                    },
                    @as(u16, ztun.attr.Type.alternate_domain) => {
                        try writer.print(
                            \\                Type: ALTERNATE-DOMAIN
                            \\                Value: {s}
                            \\
                        , .{attribute.data});
                    },
                    else => {
                        try writer.print(unknown_attribute_format, .{ attribute.type, attribute.data });
                    },
                }
            }
        }
        _ = options;
    }
};
