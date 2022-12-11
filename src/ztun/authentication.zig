// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const io = @import("io.zig");

/// Stores the parameter required for the Short-term authentication mechanism.
pub const ShortTermAuthentication = struct {
    /// Stores the password of the user.
    password: []const u8,

    /// Computes the authentication key corresponding to the stored parameters and tries to place the result in the given buffer.
    /// Returns the amount of bytes written.
    pub fn computeKey(self: ShortTermAuthentication, out: []u8) !usize {
        var stream = std.io.fixedBufferStream(out);
        try io.writeOpaqueString(self.password, stream.writer());
        return stream.getWritten().len;
    }

    /// Computes the authentication key corresponding to the stored parameters and tries to allocate the required.
    /// Returns the buffer containing the computed key.
    pub fn computeKeyAlloc(self: ShortTermAuthentication, allocator: std.mem.Allocator) ![]u8 {
        var buffer = try allocator.alloc(u8, self.password.len * 2);
        errdefer allocator.free(buffer);
        const bytes_written = try self.computeKey(buffer);
        return allocator.shrink(buffer, bytes_written);
    }
};

/// Stores the parameter required for the Long-term authentication mechanism.
pub const LongTermAuthentication = struct {
    /// Stores the username of the user.
    username: []const u8,
    /// Stores the password of the user.
    password: []const u8,
    /// Stores the realm given to the user.
    realm: []const u8,

    /// Computes the authentication key corresponding to the stored parameters and tries to place the result in the given buffer.
    /// Returns the amount of bytes written.
    pub fn computeKey(self: LongTermAuthentication, out: []u8) !usize {
        var md5_stream = io.Md5Stream.init();
        var md5_writer = md5_stream.writer();
        try md5_writer.writeAll(self.username);
        try md5_writer.writeByte(':');
        try io.writeOpaqueString(self.realm, md5_writer);
        try md5_writer.writeByte(':');
        try io.writeOpaqueString(self.password, md5_writer);
        md5_writer.context.state.final(out[0..std.crypto.hash.Md5.digest_length]);
        return std.crypto.hash.Md5.digest_length;
    }

    /// Computes the authentication key corresponding to the stored parameters and tries to allocate the required.
    /// Returns the buffer containing the computed key.
    pub fn computeKeyAlloc(self: LongTermAuthentication, allocator: std.mem.Allocator) ![]u8 {
        var buffer = try allocator.alloc(u8, std.crypto.hash.Md5.digest_length);
        errdefer allocator.free(buffer);
        const bytes_written = try self.computeKey(buffer);
        return buffer[0..bytes_written];
    }
};

/// Represents the type of authentication.
pub const AuthenticationType = enum {
    short_term,
    long_term,
};

/// Represents an authentication mechanism.
pub const Authentication = union(AuthenticationType) {
    short_term: ShortTermAuthentication,
    long_term: LongTermAuthentication,

    /// Computes the authentication key corresponding to the stored parameters and tries to place the result in the given buffer.
    /// Returns the amount of bytes written.
    pub fn computeKey(self: Authentication, out: []u8) !usize {
        return switch (self) {
            inline else => |auth| auth.computeKey(out),
        };
    }

    /// Computes the authentication key corresponding to the stored parameters and tries to allocate the required.
    /// Returns the buffer containing the computed key.
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
