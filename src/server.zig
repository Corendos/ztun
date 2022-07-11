const std = @import("std");
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

pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
    const epoll_fd = try utils.createEPoll();
    errdefer utils.close(epoll_fd) catch unreachable;

    const event_fd = try utils.createEventFd();
    errdefer utils.close(event_fd) catch unreachable;

    const socket = try ztun.net.Socket.init(.ipv4, .udp);
    errdefer socket.deinit();
    try socket.bind(config.address);

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

pub fn run() !void {}
