const std = @import("std");
const builtin = @import("builtin");

pub const IOContext = switch(builtin.os.tag) {
    .linux => @import("io/linux_io_context.zig").IOContext,
    else => @compileError(@tagName(builtin.os.tag) ++ " OS is not supported yet."),
};