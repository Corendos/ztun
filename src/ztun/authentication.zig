// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const io = @import("io.zig");
const attr = @import("attributes.zig");

/// Stores the parameter required for the Short-term authentication mechanism.
pub const ShortTermAuthenticationParameters = struct {
    /// Stores the password of the user.
    password: []const u8,

    /// Computes the authentication key corresponding to the stored parameters and tries to place the result in the given buffer.
    /// Returns the amount of bytes written.
    pub fn computeKey(self: ShortTermAuthenticationParameters, out: []u8) !usize {
        var stream = std.io.fixedBufferStream(out);
        try io.writeOpaqueString(self.password, stream.writer());
        return stream.getWritten().len;
    }

    /// Computes the authentication key corresponding to the stored parameters and tries to allocate the required.
    /// Returns the buffer containing the computed key.
    pub fn computeKeyAlloc(self: ShortTermAuthenticationParameters, allocator: std.mem.Allocator) ![]u8 {
        const buffer = try allocator.alloc(u8, self.password.len * 2);
        errdefer allocator.free(buffer);
        const bytes_written = try self.computeKey(buffer);
        return try allocator.realloc(buffer, bytes_written);
    }
};

/// Represents the type of algorithm that are supported to compute the key used in the message integrity mechanism.
pub const AlgorithmType = enum(u16) {
    md5 = 0x0001,
    sha256 = 0x0002,
    _,
};

/// Represents an algorithm and its parameters.
pub const Algorithm = struct {
    type: AlgorithmType,
    parameters: []const u8,

    /// Returns the default Algorithm given its type.
    pub fn default(algorithm_type: AlgorithmType) Algorithm {
        return switch (algorithm_type) {
            .md5 => .{ .type = algorithm_type, .parameters = &.{} },
            .sha256 => .{ .type = algorithm_type, .parameters = &.{} },
            _ => unreachable,
        };
    }
};

/// Stores the parameter required for the Long-term authentication mechanism.
pub const LongTermAuthenticationParameters = struct {
    /// Stores the username of the user.
    username: []const u8,
    /// Stores the password of the user.
    password: []const u8,
    /// Stores the realm given to the user.
    realm: []const u8,

    /// Computes the authentication key corresponding to the stored parameters and tries to place the result in the given buffer.
    /// Returns the amount of bytes written.
    pub fn computeKey(self: LongTermAuthenticationParameters, algorithm: Algorithm, out: []u8) !usize {
        return switch (algorithm.type) {
            .md5 => b: {
                var md5_stream = io.Md5Stream.init();
                var md5_writer = md5_stream.writer();
                try md5_writer.writeAll(self.username);
                try md5_writer.writeByte(':');
                try io.writeOpaqueString(self.realm, md5_writer);
                try md5_writer.writeByte(':');
                try io.writeOpaqueString(self.password, md5_writer);
                md5_writer.context.state.final(out[0..std.crypto.hash.Md5.digest_length]);
                break :b std.crypto.hash.Md5.digest_length;
            },
            .sha256 => b: {
                var sha256_stream = io.Sha256Stream.init();
                var sha256_writer = sha256_stream.writer();
                try sha256_writer.writeAll(self.username);
                try sha256_writer.writeByte(':');
                try io.writeOpaqueString(self.realm, sha256_writer);
                try sha256_writer.writeByte(':');
                try io.writeOpaqueString(self.password, sha256_writer);
                sha256_writer.context.state.final(out[0..std.crypto.hash.sha2.Sha256.digest_length]);
                break :b std.crypto.hash.sha2.Sha256.digest_length;
            },
            _ => unreachable,
        };
    }

    /// Computes the authentication key corresponding to the stored parameters and tries to allocate the required.
    /// Returns the buffer containing the computed key.
    pub fn computeKeyAlloc(self: LongTermAuthenticationParameters, allocator: std.mem.Allocator, algorithm: Algorithm) ![]u8 {
        const alloc_size = switch (algorithm.type) {
            .md5 => std.crypto.hash.Md5.digest_length,
            .sha256 => std.crypto.hash.sha2.Sha256.digest_length,
            _ => unreachable,
        };
        var buffer = try allocator.alloc(u8, alloc_size);
        errdefer allocator.free(buffer);
        const bytes_written = try self.computeKey(algorithm, buffer);
        return buffer[0..bytes_written];
    }
};

/// Represents the type of authentication.
pub const AuthenticationType = enum {
    none,
    short_term,
    long_term,
};

test "compute short-term authentication key" {
    const password = "password";
    const authentication = ShortTermAuthenticationParameters{ .password = password };
    const key = try authentication.computeKeyAlloc(std.testing.allocator);
    defer std.testing.allocator.free(key);

    const true_key = "password";

    try std.testing.expectEqualSlices(u8, true_key, key);
}

test "compute long-term authentication key using MD% algorithm" {
    const username = "user";
    const password = "pass";
    const realm = "realm";
    const authentication = LongTermAuthenticationParameters{ .username = username, .password = password, .realm = realm };
    const key = try authentication.computeKeyAlloc(std.testing.allocator, Algorithm.default(.md5));
    defer std.testing.allocator.free(key);

    const true_key = [_]u8{ 0x84, 0x93, 0xFB, 0xC5, 0x3B, 0xA5, 0x82, 0xFB, 0x4C, 0x04, 0x4C, 0x45, 0x6B, 0xDC, 0x40, 0xEB };

    try std.testing.expectEqualSlices(u8, &true_key, key);
}
