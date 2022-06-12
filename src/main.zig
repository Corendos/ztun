const std = @import("std");
const testing = std.testing;

pub const Message = struct {
    pub const Class = enum(u2) {
        request = 0b00,
        indication = 0b01,
        success_response = 0b10,
        error_response = 0b11,
    };

    pub const Method = enum(u12) {
        binding = 0b000000000001,
    };

    pub const Type = packed struct {
        value: u14,
        _reserved0: u2 = 0,

        const Self = @This();
        pub fn fromClassAndMethod(class: Class, method: Method) Self {
            // Message type is encoded as following :
            //  0                 1
            //  2  3  4 5 6 7 8 9 0 1 2 3 4 5
            // +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
            // |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
            // |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
            // +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
            const class_number = @intCast(u14, @bitCast(u2, class));
            const method_number = @intCast(u14, @bitCast(u12, method));
            const result = (method_number & 0b1111) | ((class_number & 0b1) << 4) | ((method_number & 0b1110000) << 1) | ((class_number & 0b10) << 7) | ((method_number & 0b111110000000) << 2);

            return Self{ .value = result };
        }
    };

    pub const Header = packed struct {
        const MAGIC_COOKIE = 0x2112A442; 
        transaction_id: u96,
        magic_cookie: u32 = MAGIC_COOKIE,
        message_length: u16,
        @"type": Type,
    };

    pub const Attribute = struct {
        pub const Type = enum(u16) {
            // Compression-required range (0x0000-0x7FFF)
            mapped_address = 0x0002,
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
            // Compression-optional range (0x8000-0xFFFF)
            password_algorithms = 0x8002,
            alternate_domain = 0x8003,
            software = 0x8022,
            alternate_server = 0x8023,
            fingerprint = 0x8028,
        };

        pub const Header = packed struct {
            length: u16,
            @"type": Attribute.Type,
        };

        pub const MappedAddressIPv4 = packed struct {
            address: u32,
            port: u16,
            family: u8 = 0x01,
            _reserved0: u8 = 0,
        };

        pub const MappedAddressIPv6 = packed struct {
            address: u128,
            port: u16,
            family: u8 = 0x02,
            _reserved0: u8 = 0,
        };

        pub const XorMappedAddressIPv4 = packed struct {
            x_address: u32,
            x_port: u16,
            family: u8 = 0x01,
            _reserved0: u8 = 0,
        };

        pub const XorMappedAddressIPv6 = packed struct {
            x_address: u128,
            x_port: u16,
            family: u8 = 0x02,
            _reserved0: u8 = 0,
        };
    };
};

test "expect messageTypeFromClassAndMethod correctly generates message type" {
    try std.testing.expect(Message.Type.fromClassAndMethod(Message.Class.request, Message.Method.binding).value == 0x0001);
    try std.testing.expect(Message.Type.fromClassAndMethod(Message.Class.success_response, Message.Method.binding).value == 0x0101);
}
