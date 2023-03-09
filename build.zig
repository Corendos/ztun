// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn build(b: *std.Build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary(.{ .name = "ztun", .root_source_file = std.Build.FileSource.relative("src/ztun.zig"), .target = target, .optimize = mode });
    lib.install();

    const ztun_module = b.addModule("ztun", .{ .source_file = std.Build.FileSource.relative("src/ztun.zig") });

    const server_sample_executable = b.addExecutable(.{ .name = "server", .root_source_file = std.Build.FileSource.relative("samples/server.zig"), .target = target, .optimize = mode });
    server_sample_executable.addModule("ztun", ztun_module);
    server_sample_executable.install();

    const client_sample_executable = b.addExecutable(.{ .name = "client", .root_source_file = std.Build.FileSource.relative("samples/client.zig"), .target = target, .optimize = mode });
    client_sample_executable.addModule("ztun", ztun_module);
    client_sample_executable.install();

    const ztun_tests = b.addTest(.{ .root_source_file = std.Build.FileSource.relative("src/ztun.zig"), .optimize = mode });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&ztun_tests.step);

    const server_sample_executable_run = server_sample_executable.run();
    server_sample_executable_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        server_sample_executable_run.addArgs(args);
    }

    const client_sample_executable_run = client_sample_executable.run();
    client_sample_executable_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        client_sample_executable_run.addArgs(args);
    }

    const server_sample_run_step = b.step("run_server", "Run server sample");
    server_sample_run_step.dependOn(&server_sample_executable_run.step);

    const client_sample_run_step = b.step("run_client", "Run client sample");
    client_sample_run_step.dependOn(&client_sample_executable_run.step);
}
