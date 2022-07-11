const std = @import("std");
const linux = std.os.linux;

fn createEpollFd() !i32 {
    const result = linux.epoll_create();
    const err = linux.getErrno(result);
    return switch (err) {
        .SUCCESS => @truncate(i32, @intCast(isize, result)),
        else => error.Unexpected,
    };
}

fn createEventFd() !i32 {
    const result = linux.eventfd(0, 0);
    const err = linux.getErrno(result);
    return switch (err) {
        .SUCCESS => @truncate(i32, @intCast(isize, result)),
        else => error.Unexpected,
    };
}

const EPollOp = enum(u32) {
    Add = linux.EPOLL.CTL_ADD,
    Modify = linux.EPOLL.CTL_MOD,
    Delete = linux.EPOLL.CTL_DEL,
};

fn epollControl(epoll_fd: i32, fd: i32, op: EPollOp, flags: u32) !void {
    const event = if (op == .Delete) null else &linux.epoll_event{
        .events = flags,
        .data = linux.epoll_data{ .fd = fd },
    };
    const result = linux.epoll_ctl(epoll_fd, @enumToInt(op), fd, event);
    const err = linux.getErrno(result);
    return switch (err) {
        .SUCCESS => {},
        else => error.Unexpected,
    };
}

const ReadySet = struct {
    
    const Self = @This();

    buffer: []i32,
    size: usize,

    pub fn init(capacity: usize, allocator: std.mem.Allocator) !Self {
        return Self{
            .buffer = try allocator.alloc(i32, capacity),
            .size = 0,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
    }

    pub fn count(self: *const Self) usize {
        return self.size;
    }

    pub fn add(self: *Self, fd: i32) !bool {
        var index: usize = 0;
        const insertion_index_opt = while (index < self.size) : (index += 1) {
            if (self.buffer[index] == fd) return false;

            if (self.buffer[index] > fd) {
                break index;
            }
        } else null;

        if (self.size >= self.buffer.len) return error.OutOfCapacity;

        if (insertion_index_opt) |insertion_index| {
            self.rightShiftAt(insertion_index);
            self.buffer[insertion_index] = fd;
            self.size += 1;
        } else {
            self.buffer[self.size] = fd;
            self.size += 1;
        }

        return true;
    }

    pub fn remove(self: *Self, fd: i32) bool {
        var index: usize = 0;
        const element_index_opt = while (index < self.size) : (index += 1) {
            if (self.buffer[index] == fd) break index;
        } else null;

        if (element_index_opt) |element_index| {
            self.leftShiftAt(element_index);
            self.size -= 1;
            return true;
        } else {
            return false;
        }
    }

    fn rightShiftAt(self: *Self, position: usize) void {
        var i: usize = position;
        while (i < self.size) : (i += 1) {
            const real_index = self.size - i;
            self.buffer[real_index] = self.buffer[real_index - 1];
        }
    }

    fn leftShiftAt(self: *Self, position: usize) void {
        var i: usize = position;
        while (i < self.size - 1) : (i += 1) {
            self.buffer[i] = self.buffer[i + 1];
        }
    }
};

pub fn IOContext(comptime C: anytype) type {
    return struct {
        const Self = @This();

        epoll_fd: i32,
        stop_event_fd: i32,
        allocator: std.mem.Allocator,
        fd_context: std.AutoArrayHashMap(i32, C),
        fd_context_mutex: std.Thread.Mutex = .{},

        read_ready: ReadySet,
        write_ready: ReadySet,

        pub fn init(allocator: std.mem.Allocator) !Self {
            const epoll_fd = try createEpollFd();
            errdefer _ = linux.close(epoll_fd);
            const stop_event_fd = try createEventFd();
            errdefer _ = linux.close(epoll_fd);

            try epollControl(epoll_fd, stop_event_fd, .Add, linux.EPOLL.IN);

            return Self{
                .epoll_fd = epoll_fd,
                .stop_event_fd = stop_event_fd,
                .allocator = allocator,
                .fd_context = std.AutoArrayHashMap(i32, C).init(allocator),
                .read_ready = try ReadySet.init(256, allocator),
                .write_ready = try ReadySet.init(256, allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.fd_context.deinit();
            self.read_ready.deinit(self.allocator);
            self.write_ready.deinit(self.allocator);
            _ = linux.close(self.epoll_fd);
            _ = linux.close(self.stop_event_fd);
        }

        pub fn stop(self: *Self) !void {
            std.log.debug("Stopping IO Context", .{});
            const value: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 1 };
            const result = linux.write(self.stop_event_fd, &value, value.len);
            const err = linux.getErrno(result);
            if (err != linux.E.SUCCESS) return error.Unexpected;
        }

        pub fn registerFd(self: *Self, fd: i32, context: C) !void {
            self.fd_context_mutex.lock();
            defer self.fd_context_mutex.unlock();

            try epollControl(self.epoll_fd, fd, .Add, linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.ET);

            const result = try self.fd_context.getOrPut(fd);
            if (result.found_existing) return error.Unexpected;
            result.value_ptr.* = context;
        }

        pub fn unregisterFd(self: *Self, fd: i32) !void {
            self.fd_context_mutex.lock();
            defer self.fd_context_mutex.unlock();

            if (!self.fd_context.swapRemove(fd)) return error.Unexpected;

            try epollControl(self.epoll_fd, fd, .Delete, 0);
        }

        pub fn run(self: *Self) !void {
            const context = C{};
            event_loop: while (true) {
                var events: [16]linux.epoll_event = undefined;

                const timeout: i32 = if (self.read_ready.count() > 0) 0 else -1;

                const result = linux.epoll_wait(self.epoll_fd, &events, events.len, timeout);
                const err = linux.getErrno(result);

                const event_count = switch (err) {
                    .SUCCESS => result,
                    else => return error.Unexpected,
                };

                var stop_requested = false;
                for (events[0..event_count]) |*event| {
                    if (event.data.fd == self.stop_event_fd) {
                        stop_requested = true;
                        continue;
                    }

                    if (stop_requested) {
                        onAborted(event.data.fd, &context);
                        continue;
                    }

                    if (event.events & linux.EPOLL.IN != 0) {
                        _ = try self.read_ready.add(event.data.fd);
                    }

                    if (event.events & linux.EPOLL.OUT != 0) {
                        _ = try self.write_ready.add(event.data.fd);
                    }
                }

                if (stop_requested) break :event_loop;

                try self.processReadyReads();
            }
        }

        fn processReadyReads(self: *Self) !void {
            var i: usize = 0;
            while (i < self.read_ready.count()) {
                const fd = self.read_ready.buffer[i];
                std.log.debug("fd is {}", .{fd});

                var buffer: [128]u8 = undefined;
                const result = linux.read(fd, &buffer, buffer.len);
                const err = linux.getErrno(result);

                switch (err) {
                    linux.E.SUCCESS => {
                        std.log.debug("fd {} received: {s}", .{ fd, buffer[0..result] });
                        i += 1;
                    },
                    linux.E.AGAIN => {
                        _ = self.read_ready.remove(fd);
                    },
                    else => {
                        std.log.err("Got {}", .{err});
                        return error.Unexpected;
                    },
                }
            }
        }

        fn onReadReady(fd: i32, context: *const C) void {
            std.log.debug("fd {} onReadReady", .{fd});
            _ = context;

            var buffer: [1024]u8 = undefined;
            const result = linux.read(fd, &buffer, buffer.len);
            const err = linux.getErrno(result);
            if (err != linux.E.SUCCESS) return;

            std.log.debug("fd {} received: {any}", .{ fd, buffer[0..result] });
        }

        fn onWriteReady(fd: i32, context: *const C) void {
            std.log.debug("fd {} onWriteReady", .{fd});
            _ = context;
            _ = fd;

            std.log.debug("fd {} ready to write", .{fd});
        }

        fn onAborted(fd: i32, context: *const C) void {
            _ = context;
            _ = fd;

            std.log.debug("fd {} operation aborted...", .{fd});
        }
    };
}
