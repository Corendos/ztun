const std = @import("std");

pub const SocketDomain = enum(u32) {
    ipv4 = std.os.linux.AF.INET,
    ipv6 = std.os.linux.AF.INET6,
};

pub const SocketType = enum(u32) {
    tcp = std.os.linux.SOCK.STREAM,
    udp = std.os.linux.SOCK.DGRAM,
};

const SocketOptionLevelAndName = struct {
    level: u32,
    name: u32,

    pub fn fromOption(option: SocketOption) SocketOptionLevelAndName {
        return switch (option) {
            .reuse_address => SocketOptionLevelAndName{
                .level = std.os.linux.SOL.SOCKET,
                .name = std.os.linux.SO.REUSEADDR,
            },
        };
    }
};

pub const SocketOption = union(enum) {
    const Self = @This();

    reuse_address: bool,

    pub fn writeRaw(self: *const Self, buffer: []u8) []u8 {
        return switch (self) {
            .reuse_address => |value| {
                const int_value = @intCast(c_int, @boolToInt(value));
                std.mem.writeIntSliceNative(c_int, buffer, int_value);
                buffer[0..@sizeOf(c_int)];
            },
        };
    }
};

pub const SocketCreationError = error{} || std.os.UnexpectedError;

pub const Payload = struct {
    address: std.net.Address,
    buffer: []u8,
};

pub const Socket = struct {
    const Self = @This();
    fd: i32,

    pub fn init(domain: SocketDomain, @"type": SocketType) SocketCreationError!Socket {
        const result = std.os.linux.socket(@enumToInt(domain), @enumToInt(@"type") | std.os.linux.SOCK.NONBLOCK, 0);
        const err = std.os.linux.getErrno(result);
        if (err != std.os.linux.E.SUCCESS) {
            return error.Unexpected;
        }

        return Socket{
            .fd = @truncate(i32, @intCast(isize, result)),
        };
    }

    pub fn deinit(self: *const Self) void {
        _ = std.os.linux.close(self.fd);
    }

    pub fn bind(self: *const Self, address: std.net.Address) !void {
        const result = std.os.linux.bind(self.fd, &address.any, address.getOsSockLen());
        const err = std.os.linux.getErrno(result);
        if (err != std.os.linux.E.SUCCESS) {
            return error.Unexpected;
        }
    }

    pub fn setOption(self: *const Self, option: SocketOption) !void {
        const levelAndName = SocketOptionLevelAndName.fromOption(option);
        var buffer: [128]u8 = undefined;
        const raw_option = option.writeRaw(buffer);

        const result = std.os.linux.setsockopt(self.fd, levelAndName.level, levelAndName.name, raw_option.ptr, raw_option.len);
        const err = std.os.linux.getErrno(result);
        if (err != std.os.linux.E.SUCCESS) {
            return error.Unexpected;
        }
    }

    pub fn sendTo(self: *const Self, address: std.net.Address, data: []const u8) !bool {
        const result = std.os.linux.sendto(self.fd, data.ptr, data.len, 0, &address.any, address.getOsSockLen());
        const err = std.os.linux.getErrno(result);
        return switch (err) {
            std.os.linux.E.SUCCESS => true,
            std.os.linux.E.AGAIN => false,
            else => error.Unexpected,
        };
    }

    pub fn receiveFrom(self: *const Self, buffer: []u8) !?Payload {
        var address: std.net.Address = undefined;
        var address_length: std.os.socklen_t = @sizeOf(@TypeOf(address));

        const result = std.os.linux.recvfrom(self.fd, buffer.ptr, buffer.len, 0, &address.any, &address_length);
        const err = std.os.linux.getErrno(result);
        return switch (err) {
            std.os.linux.E.SUCCESS => Payload{
                .address = address,
                .buffer = buffer[0..result],
            },
            std.os.linux.E.AGAIN => null,
            else => error.Unexpected,
        };
    }
};
