const std = @import("std");
const ztun = @import("main.zig");

const MAGIC_COOKIE = ztun.MAGIC_COOKIE;

const Self = @This();

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
    message_length: u16,
    transaction_id: u96,

    const Self = @This();
};

pub const AttributeHeader = struct {
    raw_type: u16,
    length: u16,

    pub fn read(reader: anytype) !AttributeHeader {
        return AttributeHeader{
            .raw_type = try reader.readIntBig(u16),
            .length = try reader.readIntBig(u16),
        };
    }
};

pub const AttributeType = enum(u16) {
    // Comprehension-required range (0x0000-0x7FFF)
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
    // Comprehension-optional range (0x8000-0xFFFF)
    password_algorithms = 0x8002,
    alternate_domain = 0x8003,
    software = 0x8022,
    alternate_server = 0x8023,
    fingerprint = 0x8028,
    response_origin = 0x802b,
    other_address = 0x802c,

    pub fn fromRaw(raw_type: u16) ?AttributeType {
        return std.meta.intToEnum(AttributeType, raw_type) catch null;
    }
};

pub const AttributeOrUnknown = union(enum) {
    attribute: Attribute,
    unknown: u16,
};

pub const Attribute = union(AttributeType) {
    mapped_address: ztun.attributes.MappedAddress,
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
    xor_mapped_address: ztun.attributes.XorMappedAddress,
    padding: void,
    password_algorithms: void,
    alternate_domain: void,
    software: ztun.attributes.Software,
    alternate_server: void,
    fingerprint: void,
    response_origin: ztun.attributes.ResponseOrigin,
    other_address: ztun.attributes.OtherAddress,

    pub fn readAlloc(allocator: std.mem.Allocator, reader: anytype, transaction_id: u96) !Attribute {
        return switch (tryReadAlloc(allocator, reader, transaction_id)) {
            .attribute => |attribute| attribute,
            .unknown => error.InvalidType,
        };
    }

    pub fn tryReadAlloc(allocator: std.mem.Allocator, reader: anytype, transaction_id: u96) !AttributeOrUnknown {
        _ = allocator;
        const header = try AttributeHeader.read(reader);
        const aligned_length = std.mem.alignForward(header.length, 4);

        if (AttributeType.fromRaw(header.raw_type)) |attribute_type| {
            const attribute = switch (attribute_type) {
                AttributeType.mapped_address => Attribute{ .mapped_address = try ztun.attributes.MappedAddress.read(reader) },
                AttributeType.xor_mapped_address => Attribute{ .xor_mapped_address = try ztun.attributes.XorMappedAddress.read(reader, transaction_id) },
                AttributeType.software => blk: {
                    const current_pos = reader.context.getPos() catch unreachable;
                    const end_pos = current_pos + header.length;
                    const value = try allocator.dupe(u8, reader.context.buffer[current_pos..end_pos]);
                    errdefer allocator.free(value);
                    try reader.skipBytes(aligned_length, .{});
                    break :blk Attribute{ .software = ztun.attributes.Software{ .value = value } };
                },
                AttributeType.unknown_attributes => blk: {
                    try reader.skipBytes(aligned_length, .{});
                    break :blk Attribute{ .unknown_attributes = {} };
                },
                AttributeType.response_origin => Attribute{ .response_origin = try ztun.attributes.ResponseOrigin.read(reader) },
                AttributeType.other_address => Attribute{ .other_address = try ztun.attributes.OtherAddress.read(reader) },
                else => return AttributeOrUnknown{ .unknown = header.raw_type },
            };

            return AttributeOrUnknown{ .attribute = attribute };
        }

        try reader.skipBytes(aligned_length, .{});
        return AttributeOrUnknown{ .unknown = header.raw_type };
    }

    pub fn write(self: Attribute, writer: anytype) !void {
        try writer.writeIntBig(u16, @intCast(u16, @enumToInt(self)));
        try writer.writeIntBig(u16, @intCast(u16, self.getSize()));
        switch (self) {
            AttributeType.mapped_address => |e| try e.write(writer),
            AttributeType.software => |e| try e.write(writer),
            else => unreachable,
        }
    }

    pub fn getSize(self: Attribute) usize {
        return switch (self) {
            AttributeType.mapped_address => |e| e.getSize(),
            AttributeType.software => |e| e.getSize(),
            else => 0,
        };
    }

    pub fn getPaddedSize(self: Attribute) usize {
        return switch (self) {
            AttributeType.mapped_address => |e| e.getPaddedSize(),
            AttributeType.software => |e| e.getPaddedSize(),
            else => 0,
        };
    }

    pub fn deinit(self: *const Attribute, allocator: std.mem.Allocator) void {
        switch (self.*) {
            Attribute.software => |element| {
                allocator.free(element.value);
            },
            else => {},
        }
    }
};

header: Header,
attributes: []Attribute,

pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
    for (self.attributes) |attribute| {
        attribute.deinit(allocator);
    }
    allocator.free(self.attributes);
}

pub fn write(self: *const Self, writer: anytype) !usize {
    _ = try writer.writeIntBig(u16, @as(u16, self.header.@"type".asRaw()));
    _ = try writer.writeIntBig(u16, self.header.message_length);
    _ = try writer.writeIntBig(u32, MAGIC_COOKIE);
    _ = try writer.writeIntBig(u96, self.header.transaction_id);

    for (self.attributes) |attribute| {
        try attribute.write(writer);
    }

    return writer.context.getPos() catch unreachable;
}

pub fn getBodySize(self: *const Self) usize {
    var body_size: usize = 0;
    for (self.attributes) |attribute| {
        body_size += 4 + attribute.getPaddedSize();
    }

    return body_size;
}

pub fn send(self: *const Self, network_stream: std.net.Stream) !void {
    var buffer: [576]u8 = undefined;

    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();

    const bytes_written = try self.write(writer);
    var network_writer = network_stream.writer();
    _ = try network_writer.write(buffer[0..bytes_written]);
}

pub const ReadResult = union(enum) {
    success: Self,
    errors: []u16,

    pub fn deinit(self: *const ReadResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |message| {
                message.deinit(allocator);
            },
            .errors => |errors| {
                allocator.free(errors);
            },
        }
    }
};

pub fn readAlloc(allocator: std.mem.Allocator, reader: anytype) !ReadResult {
    const header = blk: {
        const raw_type: u16 = try reader.readIntBig(u16);
        const raw_message_length: u16 = try reader.readIntBig(u16);
        const raw_magic_cookie: u32 = try reader.readIntBig(u32);
        const raw_transaction_id: u96 = try reader.readIntBig(u96);

        if (raw_type & 0b1100000000000000 != 0x0) return error.NotAStunMessage;
        if (raw_magic_cookie != MAGIC_COOKIE) return error.NotAStunMessage;

        const raw_class = Class.extractRaw(@truncate(u14, raw_type));
        const raw_method = Method.extractRaw(@truncate(u14, raw_type));

        const class = std.meta.intToEnum(Class, raw_class) catch return error.InvalidClass;
        const method = std.meta.intToEnum(Method, raw_method) catch return error.InvalidMethod;

        break :blk Header{
            .@"type" = Type{ .class = class, .method = method },
            .message_length = raw_message_length,
            .transaction_id = raw_transaction_id,
        };
    };

    var body_buffer: [556]u8 = undefined;
    const read_message_length = try reader.read(&body_buffer);
    // TODO(Corentin): Should we do something if read_message_length != header.message_length ?
    _ = read_message_length;

    // TODO(Corentin): parse the message once to get the number of attributes
    var attributes = try std.ArrayList(Attribute).initCapacity(allocator, 16);
    defer attributes.deinit();

    var unknown_attributes = try std.ArrayList(u16).initCapacity(allocator, 16);
    defer unknown_attributes.deinit();

    var body_stream = std.io.fixedBufferStream(body_buffer[0..read_message_length]);
    var body_reader = body_stream.reader();

    while (Attribute.tryReadAlloc(allocator, body_reader, header.transaction_id)) |attribute_or_unknown| switch (attribute_or_unknown) {
        .attribute => |attribute| {
            std.log.debug("Got attribute {s}", .{attribute});
            const new_attribute = try attributes.addOne();
            new_attribute.* = attribute;
        },
        .unknown => |raw_attribute_value| {
            std.log.debug("Got unknown {}", .{raw_attribute_value});
            const new_unknown_attribute = try unknown_attributes.addOne();
            new_unknown_attribute.* = raw_attribute_value;
        },
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    }

    if (unknown_attributes.items.len != 0) {
        return ReadResult{ .errors = unknown_attributes.toOwnedSlice() };
    }

    return ReadResult{
        .success = Self{
            .header = header,
            .attributes = attributes.toOwnedSlice(),
        },
    };
}

pub fn receiveAlloc(allocator: std.mem.Allocator, network_stream: std.net.Stream) !ReadResult {
    const response_buffer: []u8 = blk: {
        var buffer: [576]u8 = undefined;
        const bytes_read = try network_stream.reader().read(&buffer);
        break :blk buffer[0..bytes_read];
    };

    var response_stream = std.io.fixedBufferStream(response_buffer);
    var response_reader = response_stream.reader();

    return try readAlloc(allocator, response_reader);
}

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
