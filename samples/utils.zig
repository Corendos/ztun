// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");

const linux = std.os.linux;

pub const SocketType = enum {
    ipv4,
    ipv6,

    pub inline fn fromAddress(address: ztun.net.Address) SocketType {
        return switch (address) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
        };
    }
};

pub fn createSocket(socket_type: SocketType) !i32 {
    var result = switch (socket_type) {
        .ipv4 => linux.socket(linux.PF.INET, linux.SOCK.DGRAM, 0),
        .ipv6 => linux.socket(linux.PF.INET6, linux.SOCK.DGRAM, 0),
    };
    if (linux.getErrno(result) != linux.E.SUCCESS) {
        return error.SocketCreationFailed;
    }
    return @truncate(i32, @intCast(isize, result));
}

fn toRawAddress(address: ztun.net.Address) std.net.Address {
    return switch (address) {
        .ipv4 => std.net.Address{
            .in = std.net.Ip4Address.init(
                @bitCast([4]u8, std.mem.nativeToBig(u32, address.ipv4.value)),
                address.ipv4.port,
            ),
        },
        .ipv6 => std.net.Address{
            .in6 = std.net.Ip6Address.init(
                @bitCast([16]u8, std.mem.nativeToBig(u128, address.ipv6.value)),
                address.ipv6.port,
                address.ipv6.flowinfo,
                address.ipv6.scope_id,
            ),
        },
    };
}

fn fromRawAddress(raw_address: *std.net.Address) ztun.net.Address {
    return switch (raw_address.any.family) {
        std.os.AF.INET => ztun.net.Address{
            .ipv4 = ztun.net.Ipv4Address{
                .value = std.mem.bigToNative(u32, raw_address.in.sa.addr),
                .port = raw_address.in.getPort(),
            },
        },
        std.os.AF.INET6 => ztun.net.Address{
            .ipv6 = ztun.net.Ipv6Address{
                .value = std.mem.bigToNative(u128, @bitCast(u128, raw_address.in6.sa.addr)),
                .port = raw_address.in6.getPort(),
                .flowinfo = raw_address.in6.sa.flowinfo,
                .scope_id = raw_address.in6.sa.scope_id,
            },
        },
        else => @panic("Unsupported socket family"),
    };
}

pub fn bindSocket(socket: i32, address: ztun.net.Address) !void {
    const raw_address = toRawAddress(address);
    var result = linux.bind(socket, &raw_address.any, raw_address.getOsSockLen());
    if (linux.getErrno(result) != linux.E.SUCCESS) {
        std.log.err("{}", .{linux.getErrno(result)});
        return error.SocketBindFailed;
    }
}

pub fn sendTo(socket: i32, bytes: []const u8, address: ztun.net.Address) !void {
    const raw_address = toRawAddress(address);
    const result = linux.sendto(socket, bytes.ptr, bytes.len, 0, &raw_address.any, raw_address.getOsSockLen());
    if (linux.getErrno(result) != linux.E.SUCCESS) {
        std.log.err("{}", .{linux.getErrno(result)});
        return error.SendFailed;
    }
}

const Message = struct {
    data: []const u8,
    source: ztun.net.Address,
};

pub fn receiveFrom(socket: i32, buf: []u8) !Message {
    var buffer: [std.os.sockaddr.SS_MAXSIZE]u8 align(4) = undefined;
    var raw_address_length: linux.socklen_t = @sizeOf(@TypeOf(buffer));
    var raw_address = @ptrCast(*std.net.Address, &buffer);

    const result = linux.recvfrom(socket, buf.ptr, buf.len, 0, &raw_address.any, &raw_address_length);
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.ReceiveFailed;
    const address = addr: {
        const address = fromRawAddress(raw_address);
        if (address == .ipv6 and isIpv4MappedAddress(address.ipv6)) {
            break :addr extractIpv4MappedAddress(address.ipv6);
        }
        break :addr address;
    };

    return Message{
        .data = buf[0..result],
        .source = address,
    };
}

pub fn receive(socket: i32, buf: []u8) ![]const u8 {
    const result = linux.read(socket, buf.ptr, buf.len);
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.ReceiveFailed;
    return buf[0..result];
}

pub inline fn isIpv4MappedAddress(address: ztun.net.Ipv6Address) bool {
    return address.value & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000 == 0x0000_0000_0000_0000_0000_FFFF_0000_0000;
}

pub inline fn extractIpv4MappedAddress(address: ztun.net.Ipv6Address) ztun.net.Address {
    return .{ .ipv4 = ztun.net.Ipv4Address{ .value = @truncate(u32, address.value), .port = address.port } };
}

pub const Options = struct {
    address: ztun.net.Address,

    pub fn fromArgsAlloc(allocator: std.mem.Allocator) !Options {
        var options: Options = undefined;

        var arg_iterator = try std.process.argsWithAllocator(allocator);
        defer arg_iterator.deinit();

        _ = arg_iterator.skip();

        const raw_address = arg_iterator.next() orelse return error.MissingArgument;
        const raw_port = arg_iterator.next() orelse return error.MissingArgument;

        if (std.mem.indexOf(u8, raw_address, ":")) |_| {
            // Probably IPv6
            options.address = ztun.net.Address{
                .ipv6 = try ztun.net.Ipv6Address.parse(raw_address, try std.fmt.parseUnsigned(u16, raw_port, 10)),
            };
        } else {
            // Probably IPv4
            options.address = ztun.net.Address{
                .ipv4 = try ztun.net.Ipv4Address.parse(raw_address, try std.fmt.parseUnsigned(u16, raw_port, 10)),
            };
        }

        return options;
    }
};
