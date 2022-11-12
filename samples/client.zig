// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");

const linux = std.os.linux;

pub fn createSocket() !i32 {
    var result = linux.socket(linux.PF.INET, linux.SOCK.DGRAM, 0);
    if (linux.getErrno(result) != linux.E.SUCCESS) {
        return error.SocketCreationFailed;
    }
    return @truncate(i32, @intCast(isize, result));
}

pub fn sendTo(socket: i32, bytes: []const u8, address: ztun.net.Address) !void {
    if (address == .ipv6) @panic("Not implemented");
    var raw_address = std.net.Address{
        .in = std.net.Ip4Address.init(@bitCast([4]u8, std.mem.nativeToBig(u32, address.ipv4.value)), address.ipv4.port),
    };
    const result = linux.sendto(socket, bytes.ptr, bytes.len, 0, &raw_address.any, raw_address.getOsSockLen());
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.SendFailed;
}

pub fn receive(socket: i32, buf: []u8) ![]const u8 {
    const result = linux.read(socket, buf.ptr, buf.len);
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.ReceiveFailed;
    return buf[0..result];
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const server_address = ztun.net.Address{ .ipv4 = try ztun.net.Ipv4Address.parse("127.0.0.1", 8888) };

    var socket = try createSocket();

    var buffer = try gpa.allocator().alloc(u8, 4096);
    defer gpa.allocator().free(buffer);

    var scratch_buffer = try gpa.allocator().alloc(u8, 8192);
    defer gpa.allocator().free(scratch_buffer);

    var scratch_allocator_state = std.heap.FixedBufferAllocator.init(scratch_buffer);

    const request_message = msg: {
        var message_builder = ztun.MessageBuilder.init(scratch_allocator_state.allocator());
        defer scratch_allocator_state.reset();
        message_builder.setClass(ztun.Class.request);
        message_builder.setMethod(ztun.Method.binding);
        message_builder.randomTransactionId();
        break :msg try message_builder.build();
    };

    const raw_request_message = blk: {
        var stream = std.io.fixedBufferStream(buffer);
        try request_message.serialize(stream.writer());
        break :blk stream.getWritten();
    };

    try sendTo(socket, raw_request_message, server_address);
    const raw_message = try receive(socket, buffer);
    const message = blk: {
        var stream = std.io.fixedBufferStream(raw_message);
        break :blk try ztun.Message.deserialize(stream.reader(), scratch_allocator_state.allocator());
    };
    std.log.debug("{any}", .{message});
}
