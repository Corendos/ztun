const std = @import("std");
const MAGIC_COOKIE = @import("main.zig").MAGIC_COOKIE;

pub const IPFamily = enum(u8) {
    v4 = 0x01,
    v6 = 0x02,
};

pub const Address = union(IPFamily) {
    v4: [4]u8,
    v6: [8]u16,

    pub fn format(address: Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        switch (address) {
            .v4 => |value| {
                try writer.print("{}.{}.{}.{}", .{ value[0], value[1], value[2], value[3] });
            },
            .v6 => |value| {
                try writer.print("{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", .{
                    value[0],
                    value[1],
                    value[2],
                    value[3],
                    value[4],
                    value[5],
                    value[6],
                    value[7],
                });
            },
        }
    }
};

fn readAddress(reader: anytype, family: IPFamily) !Address {
    return switch (family) {
        .v4 => blk: {
            var raw = try reader.readBytesNoEof(4);
            break :blk Address{ .v4 = .{
                std.mem.readIntBig(u8, raw[0..1]),
                std.mem.readIntBig(u8, raw[1..2]),
                std.mem.readIntBig(u8, raw[2..3]),
                std.mem.readIntBig(u8, raw[3..4]),
            } };
        },
        .v6 => blk: {
            const raw = try reader.readBytesNoEof(16);
            break :blk Address{ .v6 = .{
                std.mem.readIntBig(u16, raw[0..2]),
                std.mem.readIntBig(u16, raw[2..4]),
                std.mem.readIntBig(u16, raw[4..6]),
                std.mem.readIntBig(u16, raw[6..8]),
                std.mem.readIntBig(u16, raw[8..10]),
                std.mem.readIntBig(u16, raw[10..12]),
                std.mem.readIntBig(u16, raw[12..14]),
                std.mem.readIntBig(u16, raw[14..16]),
            } };
        },
    };
}

pub const MappedAddress = struct {
    const Self = @This();
    port: u16,
    address: Address,

    pub fn read(reader: anytype) !Self {
        const header_raw = try reader.readBytesNoEof(4);

        const zeroes = std.mem.readIntBig(u8, header_raw[0..1]);
        const family_number = std.mem.readIntBig(u8, header_raw[1..2]);
        const port = std.mem.readIntBig(u16, header_raw[2..4]);

        if (zeroes != 0x0) return error.InvalidAttribute;

        const family = std.meta.intToEnum(IPFamily, family_number) catch {
            return error.InvalidAttribute;
        };

        const address = try readAddress(reader, family);

        return Self{ .port = port, .address = address };
    }

    pub fn write(self: *const Self, writer: anytype) !void {
        try writer.writeIntBig(u8, 0);
        try writer.writeIntBig(u8, @enumToInt(self.address));
        try writer.writeIntBig(u16, self.port);
        switch (self.address) {
            .v4 => |address| {
                try writer.writeIntBig(u8, address[0]);
                try writer.writeIntBig(u8, address[1]);
                try writer.writeIntBig(u8, address[2]);
                try writer.writeIntBig(u8, address[3]);
            },
            .v6 => unreachable,
        }
    }

    pub fn getSize(self: *const Self) usize {
        return switch (self.address) {
            .v4 => 8,
            .v6 => 20,
        };
    }

    pub fn getPaddedSize(self: *const Self) usize {
        return switch (self.address) {
            .v4 => 8,
            .v6 => 20,
        };
    }
};

pub const XorMappedAddress = struct {
    const Self = @This();
    x_port: u16,
    x_address: Address,

    pub fn read(reader: anytype, transaction_id: u96) !Self {
        _ = transaction_id;
        const header_raw = try reader.readBytesNoEof(4);

        const zeroes = std.mem.readIntBig(u8, header_raw[0..1]);
        const family_number = std.mem.readIntBig(u8, header_raw[1..2]);

        const x_port = blk: {
            var value = std.mem.readIntBig(u16, header_raw[2..4]);
            value = value ^ @as(u16, MAGIC_COOKIE >> 16);
            break :blk value;
        };

        if (zeroes != 0x0) return error.InvalidAttribute;

        const family = std.meta.intToEnum(IPFamily, family_number) catch {
            return error.InvalidAttribute;
        };

        const x_address = switch (family) {
            .v4 => blk: {
                var raw = try reader.readBytesNoEof(4);
                var xored_adress = std.mem.bytesAsValue(u32, raw[0..4]);
                xored_adress.* = xored_adress.* ^ @byteSwap(u32, @as(u32, MAGIC_COOKIE));

                break :blk Address{ .v4 = .{
                    std.mem.readIntBig(u8, raw[0..1]),
                    std.mem.readIntBig(u8, raw[1..2]),
                    std.mem.readIntBig(u8, raw[2..3]),
                    std.mem.readIntBig(u8, raw[3..4]),
                } };
            },
            .v6 => blk: {
                const raw = try reader.readBytesNoEof(16);
                break :blk Address{ .v6 = .{
                    std.mem.readIntBig(u16, raw[0..2]),
                    std.mem.readIntBig(u16, raw[2..4]),
                    std.mem.readIntBig(u16, raw[4..6]),
                    std.mem.readIntBig(u16, raw[6..8]),
                    std.mem.readIntBig(u16, raw[8..10]),
                    std.mem.readIntBig(u16, raw[10..12]),
                    std.mem.readIntBig(u16, raw[12..14]),
                    std.mem.readIntBig(u16, raw[14..16]),
                } };
            },
        };

        return Self{
            .x_port = x_port,
            .x_address = x_address,
        };
    }
};

pub const ResponseOrigin = struct {
    const Self = @This();
    port: u16,
    address: Address,

    pub fn read(reader: anytype) !Self {
        const header_raw = try reader.readBytesNoEof(4);

        const zeroes = std.mem.readIntBig(u8, header_raw[0..1]);
        const family_number = std.mem.readIntBig(u8, header_raw[1..2]);
        const port = std.mem.readIntBig(u16, header_raw[2..4]);

        if (zeroes != 0x0) return error.InvalidAttribute;

        const family = std.meta.intToEnum(IPFamily, family_number) catch {
            return error.InvalidAttribute;
        };

        const address = try readAddress(reader, family);

        return Self{ .port = port, .address = address };
    }
};

pub const OtherAddress = struct {
    const Self = @This();
    port: u16,
    address: Address,

    pub fn read(reader: anytype) !Self {
        const header_raw = try reader.readBytesNoEof(4);

        const zeroes = std.mem.readIntBig(u8, header_raw[0..1]);
        const family_number = std.mem.readIntBig(u8, header_raw[1..2]);
        const port = std.mem.readIntBig(u16, header_raw[2..4]);

        if (zeroes != 0x0) return error.InvalidAttribute;

        const family = std.meta.intToEnum(IPFamily, family_number) catch {
            return error.InvalidAttribute;
        };

        const address = try readAddress(reader, family);

        return Self{ .port = port, .address = address };
    }
};

pub const Software = struct {
    const Self = @This();

    value: []const u8,

    pub fn format(value: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        _ = value;
        try writer.print("\"{s}\"", .{value.value});
    }

    pub fn write(self: *const Self, writer: anytype) !void {
        _ = try writer.write(self.value);
        const padding_size = std.mem.alignForward(self.value.len, 4) - self.value.len;
        const pad_values = [_]u8{0, 0, 0, 0};
        _ = try writer.write(pad_values[0..padding_size]);
    }

    pub fn getSize(self: *const Self) usize {
        return self.value.len;
    }

    pub fn getPaddedSize(self: *const Self) usize {
        return std.mem.alignForward(self.value.len, 4);
    }
};
