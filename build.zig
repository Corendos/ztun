// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn module(b: *std.Build) *std.Build.Module {
    return b.addModule("ztun", std.Build.CreateModuleOptions{
        .source_file = .{ .path = thisDir() ++ "/src/ztun.zig" },
    });
}

pub fn build(b: *std.Build) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const ztun_module = module(b);

    const server_sample_executable = b.addExecutable(.{
        .name = "server",
        .root_source_file = std.Build.FileSource.relative("samples/server.zig"),
        .target = target,
        .optimize = mode,
    });
    server_sample_executable.addModule("ztun", ztun_module);
    b.installArtifact(server_sample_executable);

    const client_sample_executable = b.addExecutable(.{
        .name = "client",
        .root_source_file = std.Build.FileSource.relative("samples/client.zig"),
        .target = target,
        .optimize = mode,
    });
    client_sample_executable.addModule("ztun", ztun_module);
    b.installArtifact(client_sample_executable);

    const ztun_tests = b.addTest(.{
        .root_source_file = std.Build.FileSource.relative("src/ztun.zig"),
        .optimize = mode,
    });
    const ztun_tests_run = b.addRunArtifact(ztun_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&ztun_tests_run.step);

    const server_sample_executable_run = b.addRunArtifact(server_sample_executable);
    const client_sample_executable_run = b.addRunArtifact(client_sample_executable);
    if (b.args) |args| {
        server_sample_executable_run.addArgs(args);
        client_sample_executable_run.addArgs(args);
    }

    const server_sample_run_step = b.step("run_server", "Run server sample");
    server_sample_run_step.dependOn(&server_sample_executable_run.step);

    const client_sample_run_step = b.step("run_client", "Run client sample");
    client_sample_run_step.dependOn(&client_sample_executable_run.step);
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
