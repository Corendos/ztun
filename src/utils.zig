const std = @import("std");
const linux = std.os.linux;

pub const EPollCreateError = error{
    /// The  per-user   limit   on   the   number   of   epoll   instances   imposed   by
    /// /proc/sys/fs/epoll/max_user_instances  was encountered.  See epoll(7) for further
    /// details.
    /// Or, The per-process limit on the number of open file descriptors has been reached.
    ProcessFdQuotaExceeded,

    /// The system-wide limit on the total number of open files has been reached.
    SystemFdQuotaExceeded,

    /// There was insufficient memory to create the kernel object.
    SystemResources,
} || std.os.UnexpectedError;

pub fn createEPoll() EPollCreateError!i32 {
    const result = linux.epoll_create();
    const err = linux.getErrno(result);
    return switch (err) {
        .SUCCESS => @truncate(i32, @intCast(isize, result)),
        .INVAL => unreachable,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOMEM => error.SystemResources,
        else => error.Unexpected,
    };
}

pub const EPollCtlError = error{
    /// op was EPOLL_CTL_ADD, and the supplied file descriptor fd is  already  registered
    /// with this epoll instance.
    FileDescriptorAlreadyPresentInSet,

    /// fd refers to an epoll instance and this EPOLL_CTL_ADD operation would result in a
    /// circular loop of epoll instances monitoring one another.
    OperationCausesCircularLoop,

    /// op was EPOLL_CTL_MOD or EPOLL_CTL_DEL, and fd is not registered with  this  epoll
    /// instance.
    FileDescriptorNotRegistered,

    /// There was insufficient memory to handle the requested op control operation.
    SystemResources,

    /// The  limit  imposed  by /proc/sys/fs/epoll/max_user_watches was encountered while
    /// trying to register (EPOLL_CTL_ADD) a new file descriptor on  an  epoll  instance.
    /// See epoll(7) for further details.
    UserResourceLimitReached,

    /// The target file fd does not support epoll.  This error can occur if fd refers to,
    /// for example, a regular file or a directory.
    FileDescriptorIncompatibleWithEpoll,
} || std.os.UnexpectedError;

const EPollOp = enum(u32) {
    Add = linux.EPOLL.CTL_ADD,
    Modify = linux.EPOLL.CTL_MOD,
    Delete = linux.EPOLL.CTL_DEL,
};

pub fn epollControl(epoll_fd: i32, op: EPollOp, fd: i32, event: ?*linux.epoll_event) EPollCtlError!void {
    const result = linux.epoll_ctl(epoll_fd, @enumToInt(op), fd, event);
    const err = linux.getErrno(result);
    return switch (err) {
        .SUCCESS => {},
        .EXIST => error.FileDescriptorAlreadyPresentInSet,
        .INVAL => unreachable,
        .LOOP => error.OperationCausesCircularLoop,
        .NOENT => error.FileDescriptorNotRegistered,
        .NOMEM => error.SystemResources,
        .NOSPC => error.UserResourceLimitReached,
        .PERM => error.FileDescriptorIncompatibleWithEpoll,
        else => error.Unexpected,
    };
}

pub const EPollWaitError = error{
    /// The call was interrupted by a signal handler before either (1) any of the requested
    /// events occurred or (2) the timeout expired; see signal(7).
    Interrupted,
} || std.os.UnexpectedError;

pub fn epollWait(epoll_fd: i32, events: []linux.epoll_event, timeout: i32) EPollWaitError!usize {
    const result = linux.epoll_wait(epoll_fd, events.ptr, @intCast(u32, events.len), timeout);

    return switch (linux.getErrno(result)) {
        .SUCCESS => result,
        .INTR => error.Interrupted,
        else => error.Unexpected,
    };
}

pub const CloseError = error{} || std.os.UnexpectedError;

pub fn close(fd: i32) CloseError!void {
    const result = linux.close(fd);
    switch (linux.getErrno(result)) {
        .SUCCESS => return,
        .BADF => unreachable,
        .INTR => return,
        .IO => unreachable,
        .NOSPC => unreachable,
        else => |err| {
            std.log.err("Got unexpected error code: {}", .{err});
            return error.Unexpected;
        },
    }
}

pub const EventFdError = error{
    /// The per-process limit on the number of open file descriptors has been reached.
    ProcessFdQuotaExceeded,

    /// The system-wide limit on the total number of open files has been reached.
    SystemFdQuotaExceeded,

    /// Could not mount (internal) anonymous inode device.
    NoDevice,

    /// There was insufficient memory to create a new eventfd file descriptor.
    SystemResources,
} || std.os.UnexpectedError;

pub fn createEventFd() EventFdError!i32 {
    const result = linux.eventfd(0, 0);
    const err = linux.getErrno(result);
    return switch (err) {
        .SUCCESS => @truncate(i32, @intCast(isize, result)),
        .INVAL => unreachable,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NODEV => error.NoDevice,
        .NOMEM => error.SystemResources,
        else => error.Unexpected,
    };
}
