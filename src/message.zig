const std = @import("std");

pub const MAGIC_COOKIE = 0x2112A442;

pub const attributes = @import("attributes.zig");

pub const Class = enum(u2) {
    request = 0b00,
    indication = 0b01,
    success_response = 0b10,
    error_response = 0b11,

    pub fn extractRaw(source: u14) u2 {
        return @truncate(u2, ((source & 0b10000) >> 4) | ((source & 0b100000000) >> 7));
    }

    pub fn extract(source: Type) Class {
        return @intToEnum(Class, Class.extractRaw(source));
    }
};

pub const Method = enum(u12) {
    binding = 0b000000000001,

    pub fn extractRaw(source: u14) u12 {
        return @truncate(u12, (source & 0b1111) | ((source & 0b11100000) >> 1) | ((source & 0b11111000000000) >> 2));
    }

    pub fn extract(source: Type) Method {
        return @intToEnum(Method, Method.extractRaw(source));
    }
};

pub const Type = struct {
    class: Class,
    method: Method,

    pub fn asRaw(self: *const Type) u14 {
        // Message type is encoded as following :
        //  0                 1
        //  2  3  4 5 6 7 8 9 0 1 2 3 4 5
        // +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
        // |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
        // |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
        // +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
        const class_number = @intCast(u14, @bitCast(u2, self.class));
        const method_number = @intCast(u14, @bitCast(u12, self.method));
        return (method_number & 0b1111) | ((class_number & 0b1) << 4) | ((method_number & 0b1110000) << 1) | ((class_number & 0b10) << 7) | ((method_number & 0b111110000000) << 2);
    }
};

pub const Header = struct {
    @"type": Type,
    transaction_id: u96,

    const Self = @This();
};

pub const AttributeType = enum(u16) {
    // Compression-required range (0x0000-0x7FFF)
    mapped_address = 0x0001,
    change_request = 0x0003,
    username = 0x0006,
    message_integrity = 0x0008,
    error_code = 0x0009,
    unknown_attributes = 0x000A,
    realm = 0x0014,
    nonce = 0x0015,
    message_integrity_sha256 = 0x001C,
    password_algorithm = 0x001D,
    userhash = 0x001E,
    xor_mapped_address = 0x0020,
    padding = 0x0027,
    // Compression-optional range (0x8000-0xFFFF)
    password_algorithms = 0x8002,
    alternate_domain = 0x8003,
    software = 0x8022,
    alternate_server = 0x8023,
    fingerprint = 0x8028,
    response_origin = 0x802b,
    other_address = 0x802c,
};

pub const Attribute = union(AttributeType) {
    mapped_address: attributes.MappedAddress,
    change_request: void,
    username: void,
    message_integrity: void,
    error_code: void,
    unknown_attributes: void,
    realm: void,
    nonce: void,
    message_integrity_sha256: void,
    password_algorithm: void,
    userhash: void,
    xor_mapped_address: attributes.XorMappedAddress,
    padding: void,
    password_algorithms: void,
    alternate_domain: void,
    software: attributes.Software,
    alternate_server: void,
    fingerprint: void,
    response_origin: attributes.ResponseOrigin,
    other_address: attributes.OtherAddress,

    pub fn read(allocator: std.mem.Allocator, reader: anytype, transaction_id: u96) !Attribute {
        const raw_buffer = try reader.readBytesNoEof(4);
        const attribute_type_number = std.mem.readIntBig(u16, raw_buffer[0..2]);
        const length = std.mem.readIntBig(u16, raw_buffer[2..4]);

        const attribute_type = std.meta.intToEnum(AttributeType, attribute_type_number) catch {
            return error.InvalidType;
        };

        const aligned_length = std.mem.alignForward(length, 4);

        return switch (attribute_type) {
            AttributeType.mapped_address => Attribute{ .mapped_address = try attributes.MappedAddress.read(reader) },
            AttributeType.xor_mapped_address => Attribute{ .xor_mapped_address = try attributes.XorMappedAddress.read(reader, transaction_id) },
            AttributeType.software => blk: {
                const current_pos = reader.context.getPos() catch unreachable;
                const end_pos = current_pos + length;
                const value = try allocator.dupe(u8, reader.context.buffer[current_pos..end_pos]);
                try reader.skipBytes(aligned_length, .{});
                break :blk Attribute{ .software = attributes.Software{ .value = value } };
            },
            AttributeType.unknown_attributes => blk: {
                try reader.skipBytes(aligned_length, .{});
                break :blk Attribute{ .unknown_attributes = {} };
            },
            AttributeType.response_origin => Attribute{ .response_origin = try attributes.ResponseOrigin.read(reader) },
            AttributeType.other_address => Attribute{ .other_address = try attributes.OtherAddress.read(reader) },
            else => error.UnsupportedAttribute,
        };
    }

    pub fn write(self: Attribute, writer: anytype) !void {
        _ = self;
        _ = writer;
        unreachable;
    }

    pub fn size(self: Attribute) u16 {
        return switch (self) {
            else => 0,
        };
    }
};

test "message type generation and message class and method extraction" {
    const message_type1 = Type{ .class = Class.request, .method = Method.binding };
    try std.testing.expect(Class.extract(message_type1) == .request);
    try std.testing.expect(Method.extract(message_type1) == .binding);

    const message_type2 = Type{ .class = Class.success_response, .method = Method.binding };
    try std.testing.expect(Class.extract(message_type2) == .success_response);
    try std.testing.expect(Method.extract(message_type2) == .binding);
}

test "reading invalid header" {
    const dummy = [2]u16{ 0xBABE, 0x1000 };
    var stream = std.io.fixedBufferStream(std.mem.asBytes(&dummy));
    var reader = stream.reader();
    try std.testing.expectError(error.InvalidType, Header.read(reader));
}
