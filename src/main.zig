// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun.zig");
const build_options = @import("build_options");
const linux = std.os.linux;

pub fn createSocket() !i32 {
    var result = linux.socket(linux.PF.INET6, linux.SOCK.DGRAM, 0);
    if (linux.getErrno(result) != linux.E.SUCCESS) {
        return error.SocketCreationFailed;
    }
    return @truncate(i32, @intCast(isize, result));
}

pub fn sendTo(socket: i32, bytes: []const u8, address: std.net.Address) !void {
    const result = linux.sendto(socket, bytes.ptr, bytes.len, 0, &address.any, address.getOsSockLen());
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.SendFailed;
}

const Packet = struct {
    data: []const u8,
    source: std.net.Address,
};

pub fn receiveFrom(socket: i32, buf: []u8) !Packet {
    var address_length: linux.socklen_t = @sizeOf(linux.sockaddr);
    var address: linux.sockaddr = undefined;

    const result = linux.recvfrom(socket, buf.ptr, buf.len, 0, &address, &address_length);
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.ReceiveFailed;

    return Packet{
        .data = buf[0..result],
        .source = std.net.Address.initPosix(@alignCast(4, &address)),
    };
}

pub fn doRequest(socket: i32, allocator: std.mem.Allocator) !void {
    var message_builder = ztun.MessageBuilder.init(allocator);
    message_builder.setClass(ztun.Class.request);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.randomTransactionId();
    try message_builder.addAttribute(ztun.Attribute{ .software = ztun.SoftwareAttribute{ .value = std.fmt.comptimePrint("ztun v{}", .{build_options.version}) } });

    const request = try message_builder.build();
    std.log.debug("Request:\n{}", .{request});

    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    try request.serialize(stream.writer());

    //try sendTo(socket, stream.getWritten(), try std.net.Address.parseIp4("108.177.15.127", 19302));
    try sendTo(socket, stream.getWritten(), try std.net.Address.parseIp6("2a00:1450:400c:c0c::7f", 19302));
}

pub fn handleResponse(socket: i32, allocator: std.mem.Allocator) !void {
    var buffer: [1024]u8 = undefined;
    const packet = try receiveFrom(socket, &buffer);

    var stream = std.io.fixedBufferStream(packet.data);
    const result = try ztun.deserialization.deserialize(stream.reader(), allocator);
    std.log.debug(
        \\Response:
        \\{}
        \\
        \\Errors: {any}
    , .{ result.message, result.unknown_attributes });

    //for (response.attributes) |attribute| {
    //    if (attribute == .xor_mapped_address) {
    //        const decoded_attribute = attribute.xor_mapped_address.decode(response.transaction_id);
    //        switch (decoded_attribute.family) {
    //            .ipv4 => |raw_address| {
    //                const address = std.net.Ip4Address.init(@bitCast([4]u8, std.mem.nativeToBig(u32, raw_address)), decoded_attribute.port);
    //                std.log.debug("{}", .{address});
    //            },
    //            .ipv6 => |raw_address| {
    //                const address = std.net.Ip6Address.init(@bitCast([16]u8, std.mem.nativeToBig(u128, raw_address)), decoded_attribute.port, 0, 0);
    //                std.log.debug("{}", .{address});
    //            },
    //        }
    //    }
    //}
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var arena_state = std.heap.ArenaAllocator.init(gpa.allocator());
    //defer arena_state.deinit();

    var socket = try createSocket();
    try doRequest(socket, arena_state.allocator());
    try handleResponse(socket, arena_state.allocator());
}
