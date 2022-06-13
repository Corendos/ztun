const std = @import("std");
const testing = std.testing;

pub const message = @import("message.zig");

pub const Request = struct {
    header: message.Header,
    attributes: []message.Attribute,
};

pub fn sendRequest(request: Request, network_stream: std.net.Stream) !void {
    var buffer: [576]u8 = undefined;

    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();

    var message_length: u16 = 0;
    for (request.attributes) |attribute| {
        // Attribute header is 4 bytes (Type + length)
        message_length += 4;
        message_length += attribute.size();
    }

    _ = try writer.writeIntBig(u16, @as(u16, request.header.@"type".asRaw()));
    _ = try writer.writeIntBig(u16, message_length);
    _ = try writer.writeIntBig(u32, message.MAGIC_COOKIE);
    _ = try writer.writeIntBig(u96, request.header.transaction_id);

    for (request.attributes) |attribute| {
        try attribute.write(writer);
    }

    const bytes_written = writer.context.getPos() catch unreachable;

    var network_writer = network_stream.writer();
    _ = try network_writer.write(buffer[0..bytes_written]);
}

pub const Response = struct {
    const Self = @This();

    header: message.Header,
    attributes: []message.Attribute,

    storage: []u8,

    pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
    }
};

pub fn receiveResponse(allocator: std.mem.Allocator, network_stream: std.net.Stream) !Response {
    const response_buffer: []u8 = blk: {
        var buffer: [576]u8 = undefined;
        const bytes_read = try network_stream.reader().read(&buffer);
        break :blk buffer[0..bytes_read];
    };

    var response_stream = std.io.fixedBufferStream(response_buffer);
    var response_reader = response_stream.reader();
    var message_length: u16 = 0;
    const header = blk: {
        const raw_type: u16 = try response_reader.readIntBig(u16);
        const raw_message_length: u16 = try response_reader.readIntBig(u16);
        const raw_magic_cookie: u32 = try response_reader.readIntBig(u32);
        const raw_transaction_id: u96 = try response_reader.readIntBig(u96);

        if (raw_type & 0b1100000000000000 != 0x0) return error.NotAStunMessage;
        if (raw_magic_cookie != message.MAGIC_COOKIE) return error.NotAStunMessage;

        const raw_class = message.Class.extractRaw(@truncate(u14, raw_type));
        const raw_method = message.Method.extractRaw(@truncate(u14, raw_type));

        const class = std.meta.intToEnum(message.Class, raw_class) catch return error.InvalidClass;
        const method = std.meta.intToEnum(message.Method, raw_method) catch return error.InvalidMethod;

        // TODO(Corentin): not optimal
        message_length = raw_message_length;
        break :blk message.Header{
            .@"type" = message.Type{ .class = class, .method = method },
            .transaction_id = raw_transaction_id,
        };
    };

    var storage: []u8 = try allocator.alloc(u8, 1024);
    errdefer allocator.free(storage);

    var storage_allocator = std.heap.FixedBufferAllocator.init(storage);

    var attributes = try storage_allocator.allocator().alloc(message.Attribute, 16);

    const response_body = response_buffer[20..(20 + message_length)];
    var stream = std.io.fixedBufferStream(response_body);
    var reader = stream.reader();

    var current_attribute_index: u8 = 0;
    while (true) : (current_attribute_index += 1) {
        attributes[current_attribute_index] = message.Attribute.read(storage_allocator.allocator(), reader, header.transaction_id) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
    }

    return Response{
        .header = header,
        .attributes = attributes[0..current_attribute_index],
        .storage = storage,
    };
}
