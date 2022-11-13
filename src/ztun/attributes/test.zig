// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const attr = @import("../attributes.zig");
const ztun = @import("../lib.zig");

test "MAPPED-ADDRESS deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x01,
        0x00, 0x08,
        // Padding
        0x00,
        // Family type
        0x01,
        // Port
        0x01, 0x02,
        // Address
        127,  0,
        0,    1,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.mapped_address, attribute);
    try std.testing.expectEqual(@as(u16, 0x0102), attribute.mapped_address.port);
    try std.testing.expectEqual(attr.AddressFamilyType.ipv4, attribute.mapped_address.family);
    try std.testing.expectEqual(@as(u32, 0x7F000001), attribute.mapped_address.family.ipv4);
}

test "XOR-MAPPED-ADDRESS deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x20,
        0x00, 0x08,
        // Padding
        0x00,
        // Family type
        0x01,
        // X-Port
        0x20, 0x10,
        // X-Address
        0x5E, 0x12,
        0xA4, 0x43,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.xor_mapped_address, attribute);
    try std.testing.expectEqual(@as(u16, 0x2010), attribute.xor_mapped_address.x_port);
    try std.testing.expectEqual(attr.AddressFamilyType.ipv4, attribute.xor_mapped_address.x_family);
    try std.testing.expectEqual(@as(u32, 0x5E12A443), attribute.xor_mapped_address.x_family.ipv4);

    const decoded_attribute = attribute.xor_mapped_address.decode(0x0);
    try std.testing.expectEqual(@as(u16, 0x0102), decoded_attribute.port);
    try std.testing.expectEqual(attr.AddressFamilyType.ipv4, decoded_attribute.family);
    try std.testing.expectEqual(@as(u32, 0x7F000001), decoded_attribute.family.ipv4);
}

test "USERNAME deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x06,
        0x00,
        0x04,
        // Value
        @as(u8, 'z'),
        @as(u8, 't'),
        @as(u8, 'u'),
        @as(u8, 'n'),
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.username, attribute);
    try std.testing.expectEqualStrings("ztun", attribute.username.value);
}

test "USERHASH deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x1E,
        0x00,
        0x04,
        // Value
        @as(u8, 'a'),
        @as(u8, 'b'),
        @as(u8, 'c'),
        @as(u8, 'd'),
        @as(u8, 'e'),
        @as(u8, 'f'),
        @as(u8, 'g'),
        @as(u8, 'h'),
        @as(u8, 'i'),
        @as(u8, 'j'),
        @as(u8, 'k'),
        @as(u8, 'l'),
        @as(u8, 'm'),
        @as(u8, 'n'),
        @as(u8, 'o'),
        @as(u8, 'p'),
        @as(u8, 'q'),
        @as(u8, 'r'),
        @as(u8, 's'),
        @as(u8, 't'),
        @as(u8, 'u'),
        @as(u8, 'v'),
        @as(u8, 'w'),
        @as(u8, 'x'),
        @as(u8, 'y'),
        @as(u8, 'z'),
        @as(u8, 'a'),
        @as(u8, 'b'),
        @as(u8, 'c'),
        @as(u8, 'd'),
        @as(u8, 'e'),
        @as(u8, 'f'),
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.userhash, attribute);
    try std.testing.expectEqualStrings("abcdefghijklmnopqrstuvwxyzabcdef", &attribute.userhash.value);
}

// NOTE(Corentin): Hash is the SHA-1 of "ztun"

test "MESSAGE-INTEGRITY deserialization" {
    const hash = [_]u8{
        0x43,
        0x23,
        0xc5,
        0x7d,
        0x5d,
        0x67,
        0x74,
        0xac,
        0x3e,
        0xdb,
        0xcc,
        0x0a,
        0x1d,
        0x48,
        0xc2,
        0xd2,
        0x52,
        0x78,
        0x3e,
        0xa4,
    };

    const buffer = [_]u8{
        // Header
        0x00,
        0x08,
        0x00,
        0x14,
        // Value
        0x43,
        0x23,
        0xc5,
        0x7d,
        0x5d,
        0x67,
        0x74,
        0xac,
        0x3e,
        0xdb,
        0xcc,
        0x0a,
        0x1d,
        0x48,
        0xc2,
        0xd2,
        0x52,
        0x78,
        0x3e,
        0xa4,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.message_integrity, attribute);
    try std.testing.expectEqualSlices(u8, &hash, &attribute.message_integrity.value);
}

// NOTE(Corentin): Hash is the 20 first bytes of SHA-256 of "ztun"
test "MESSAGE-INTEGRITY-SHA256 deserialization" {
    const hash = [_]u8{
        0x4d,
        0xff,
        0xed,
        0xda,
        0x21,
        0x1d,
        0x83,
        0x6d,
        0x26,
        0x12,
        0x92,
        0x2e,
        0x3d,
        0xa5,
        0x87,
        0x02,
        0x5d,
        0x18,
        0xee,
        0xec,
    };

    const buffer = [_]u8{
        // Header
        0x00,
        0x1C,
        0x00,
        0x14,
        // Value
        0x4d,
        0xff,
        0xed,
        0xda,
        0x21,
        0x1d,
        0x83,
        0x6d,
        0x26,
        0x12,
        0x92,
        0x2e,
        0x3d,
        0xa5,
        0x87,
        0x02,
        0x5d,
        0x18,
        0xee,
        0xec,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.message_integrity_sha256, attribute);
    try std.testing.expectEqualSlices(u8, &hash, attribute.message_integrity_sha256.value);
}

test "FINGERPRINT deserialization" {
    const buffer = [_]u8{
        // Header
        0x80,
        0x28,
        0x00,
        0x04,
        // Value
        0x01,
        0x02,
        0x03,
        0x04,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.fingerprint, attribute);
    try std.testing.expectEqual(@as(u32, 0x01020304), attribute.fingerprint.value);
}

test "ERROR-CODE deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x09,
        0x00,
        0x0A,
        // Class and number
        0x00,
        0x00,
        4,
        20,
    } ++ "reason" ++ [_]u8{ 0, 0 };

    var stream = std.io.fixedBufferStream(buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.error_code, attribute);
    try std.testing.expectEqual(attr.RawErrorCode.unknown_attribute, attribute.error_code.value);
    try std.testing.expectEqualStrings("reason", attribute.error_code.reason);
}

test "REALM deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x14,
        0x00,
        0x05,
        // Value
        @as(u8, 'r'),
        @as(u8, 'e'),
        @as(u8, 'a'),
        @as(u8, 'l'),
        @as(u8, 'm'),
        // Padding
        0,
        0,
        0,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.realm, attribute);
    try std.testing.expectEqualStrings("realm", attribute.realm.value);
}

test "NONCE deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x15,
        0x00,
        0x05,
        // Value
        @as(u8, 'n'),
        @as(u8, 'o'),
        @as(u8, 'n'),
        @as(u8, 'c'),
        @as(u8, 'e'),
        // Padding
        0,
        0,
        0,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.nonce, attribute);
    try std.testing.expectEqualStrings("nonce", attribute.nonce.value);
}

test "PASSWORD-ALGORITHMS deserialization" {
    const buffer = [_]u8{
        // Header
        0x80, 0x02,
        0x00, 0x08,
        // Type MD5
        0x00, 0x01,
        // Length
        0x00, 0x00,
        // Empty parameters
        // Type SHA256
        0x00, 0x02,
        // Length
        0x00,
        0x00,
        // Empty parameters
    };

    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);
    try std.testing.expectEqual(attr.Type.password_algorithms, attribute);
    try std.testing.expectEqual(@as(usize, 2), attribute.password_algorithms.algorithms.len);
    try std.testing.expectEqual(attr.AlgorithmType.md5, attribute.password_algorithms.algorithms[0]);
    try std.testing.expectEqual(attr.AlgorithmType.sha256, attribute.password_algorithms.algorithms[1]);
}

test "PASSWORD-ALGORITHM deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x1D,
        0x00, 0x04,
        // Type MD5
        0x00, 0x01,
        // Length
        0x00,
        0x00,
        // Empty parameters
    };

    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);
    try std.testing.expectEqual(attr.Type.password_algorithm, attribute);
    try std.testing.expectEqual(attr.AlgorithmType.md5, attribute.password_algorithm.algorithm);
}

test "UNKNOWN-ATTRIBUTES deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x0A,
        0x00, 0x08,
        // Attribute 1
        0x7F, 0x00,
        // Attribute 2
        0x7F, 0x01,
        // Attribute 3
        0x7F, 0x02,
        // Attribute 4
        0x7F, 0x03,
    };

    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);
    try std.testing.expectEqual(attr.Type.unknown_attributes, attribute);
    try std.testing.expectEqual(@as(usize, 4), attribute.unknown_attributes.attribute_types.len);

    try std.testing.expectEqual(@as(u16, 0x7F00), attribute.unknown_attributes.attribute_types[0]);
    try std.testing.expectEqual(@as(u16, 0x7F01), attribute.unknown_attributes.attribute_types[1]);
    try std.testing.expectEqual(@as(u16, 0x7F02), attribute.unknown_attributes.attribute_types[2]);
    try std.testing.expectEqual(@as(u16, 0x7F03), attribute.unknown_attributes.attribute_types[3]);
}

test "SOFTWARE deserialization" {
    const buffer = [_]u8{
        // Header
        0x80,
        0x22,
        0x00,
        0x08,
        // Value
        @as(u8, 's'),
        @as(u8, 'o'),
        @as(u8, 'f'),
        @as(u8, 't'),
        @as(u8, 'w'),
        @as(u8, 'a'),
        @as(u8, 'r'),
        @as(u8, 'e'),
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.software, attribute);
    try std.testing.expectEqualStrings("software", attribute.software.value);
}

test "ALTERNATE-SERVER deserialization" {
    const buffer = [_]u8{
        // Header
        0x80, 0x23,
        0x00, 0x08,
        // Padding
        0x00,
        // Family type
        0x01,
        // Port
        0x01, 0x02,
        // Address
        127,  0,
        0,    1,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.alternate_server, attribute);
    try std.testing.expectEqual(@as(u16, 0x0102), attribute.alternate_server.port);
    try std.testing.expectEqual(attr.AddressFamilyType.ipv4, attribute.alternate_server.family);
    try std.testing.expectEqual(@as(u32, 0x7F000001), attribute.alternate_server.family.ipv4);
}

test "ALTERNATE-DOMAIN deserialization" {
    const buffer = [_]u8{
        // Header
        0x80,
        0x03,
        0x00,
        0x07,
        // Value
        @as(u8, 'l'),
        @as(u8, 'o'),
        @as(u8, 's'),
        @as(u8, 't'),
        @as(u8, '.'),
        @as(u8, 'i'),
        @as(u8, 'o'),
        // Padding
        0,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try ztun.Attribute.deserialize(stream.reader(), std.testing.allocator);
    defer attribute.deinit(std.testing.allocator);

    try std.testing.expectEqual(attr.Type.alternate_domain, attribute);
    try std.testing.expectEqualStrings("lost.io", attribute.alternate_domain.value);
}
