// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const io = @import("io.zig");

pub const ShortTermAuthentication = struct {
    password: []const u8,

    pub fn computeKey(self: ShortTermAuthentication, out: []u8) ![]u8 {
        var stream = std.io.fixedBufferStream(out);
        try io.writeOpaqueString(self.password, stream.writer());
        return stream.getWritten();
    }

    pub fn computeKeyAlloc(self: ShortTermAuthentication, allocator: std.mem.Allocator) ![]u8 {
        var buffer = try allocator.alloc(u8, self.password.len * 2);
        errdefer allocator.free(buffer);
        return self.computeKey(buffer);
    }
};

pub const LongTermAuthentication = struct {
    username: []const u8,
    password: []const u8,
    realm: []const u8,

    pub fn computeKey(self: LongTermAuthentication, out: []u8) ![]u8 {
        var md5_stream = io.Md5Stream.init();
        var md5_writer = md5_stream.writer();
        try md5_writer.writeAll(self.username);
        try md5_writer.writeByte(':');
        try io.writeOpaqueString(self.realm, md5_writer);
        try md5_writer.writeByte(':');
        try io.writeOpaqueString(self.password, md5_writer);
        md5_writer.context.state.final(out[0..std.crypto.hash.Md5.digest_length]);
        return out[0..std.crypto.hash.Md5.digest_length];
    }

    pub fn computeKeyAlloc(self: LongTermAuthentication, allocator: std.mem.Allocator) ![]u8 {
        const guessed_size = self.username.len + self.realm.len + self.password.len;
        var buffer = try allocator.alloc(u8, guessed_size * 2);
        errdefer allocator.free(buffer);
        return self.computeKey(buffer);
    }
};

pub const AuthenticationType = enum {
    short_term,
    long_term,
};

pub const Authentication = union(AuthenticationType) {
    short_term: ShortTermAuthentication,
    long_term: LongTermAuthentication,

    pub fn computeKey(self: Authentication, out: []u8) ![]u8 {
        return switch (self) {
            inline else => |auth| auth.computeKey(out),
        };
    }

    pub fn computeKeyAlloc(self: Authentication, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            inline else => |auth| auth.computeKeyAlloc(allocator),
        };
    }
};

test "compute short-term authentication key" {
    const password = "password";
    const authentication = ShortTermAuthentication{ .password = password };
    const key = try authentication.computeKeyAlloc(std.testing.allocator);
    defer std.testing.allocator.free(key);

    const true_key = "password";

    try std.testing.expectEqualSlices(u8, true_key, key);
}

test "compute long-term authentication key" {
    const username = "username";
    const password = "password";
    const realm = "realm";
    const authentication = LongTermAuthentication{ .username = username, .password = password, .realm = realm };
    const key = try authentication.computeKeyAlloc(std.testing.allocator);
    defer std.testing.allocator.free(key);

    const true_key = [_]u8{ 0x66, 0x99, 0x93, 0x43, 0x28, 0x1b, 0x26, 0x24, 0x58, 0x5f, 0xd5, 0x8c, 0xc9, 0xd3, 0x6d, 0xfc };

    try std.testing.expectEqualSlices(u8, &true_key, key);
}
