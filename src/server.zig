const std = @import("std");
const linux = std.os.linux;
const ztun = @import("main.zig");
const utils = @import("utils.zig");

const Self = @This();

pub const Config = struct {
    address: std.net.Address,
};

allocator: std.mem.Allocator,
config: Config,
socket: ztun.net.Socket,
event_fd: i32,
epoll_fd: i32,
read_ready: bool = false,
write_ready: bool = false,

pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
    const epoll_fd = try utils.createEPoll();
    errdefer utils.close(epoll_fd) catch unreachable;

    const event_fd = try utils.createEventFd();
    errdefer utils.close(event_fd) catch unreachable;

    const socket = try ztun.net.Socket.init(.ipv4, .udp);
    errdefer socket.deinit();
    try socket.bind(config.address);

    var event = linux.epoll_event{
        .events = linux.EPOLL.IN,
        .data = .{
            .fd = event_fd,
        },
    };
    try utils.epollControl(epoll_fd, .Add, event_fd, &event);

    event = linux.epoll_event{
        .events = linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.ET,
        .data = .{
            .fd = socket.fd,
        },
    };
    try utils.epollControl(epoll_fd, .Add, socket.fd, &event);

    return Self{
        .allocator = allocator,
        .config = config,
        .socket = socket,
        .event_fd = event_fd,
        .epoll_fd = epoll_fd,
    };
}

pub fn deinit(self: *const Self) void {
    self.socket.deinit();
    utils.close(self.event_fd) catch unreachable;
    utils.close(self.epoll_fd) catch unreachable;
}

pub fn stop(self: *Self) !void {
    const value: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 1 };
    const result = linux.write(self.event_fd, &value, value.len);
    switch (linux.getErrno(result)) {
        .SUCCESS => return,
        else => return error.Unexpected,
    }
}

pub fn run(self: *Self) !void {
    var running = true;
    while (running) {
        var events: [16]linux.epoll_event = undefined;
        const timeout: i32 = if (self.read_ready) 0 else -1;
        const event_count = utils.epollWait(self.epoll_fd, &events, timeout) catch |err| switch (err) {
            error.Interrupted => break,
            else => return err,
        };

        for (events[0..event_count]) |event| {
            if (event.data.fd == self.event_fd) {
                running = false;
                continue;
            }

            if (event.data.fd == self.socket.fd) {
                if (event.events & linux.EPOLL.IN != 0) {
                    self.read_ready = true;
                }

                if (event.events & linux.EPOLL.OUT != 0) {
                    self.write_ready = true;
                }

                if (event.events & linux.EPOLL.HUP != 0 or event.events & linux.EPOLL.ERR != 0) {
                    running = false;
                    continue;
                }
            }
        }

        if (self.read_ready) {
            var buffer: [512]u8 = undefined;
            const payload_opt = try self.socket.receiveFrom(&buffer);
            if (payload_opt) |payload| {
                std.log.debug("Received message from {}: {any}", .{ payload.address, payload.buffer });
            } else {
                self.read_ready = false;
            }
        }
    }
}
