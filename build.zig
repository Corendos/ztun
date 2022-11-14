// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("ztun", "src/ztun.zig");
    lib.setBuildMode(mode);
    lib.setTarget(target);
    lib.install();

    const ztun_package = std.build.Pkg{
        .name = "ztun",
        .source = .{ .path = "src/ztun.zig" },
    };

    const server_sample_executable = b.addExecutable("server", "samples/server.zig");
    server_sample_executable.addPackage(ztun_package);
    server_sample_executable.setBuildMode(mode);
    server_sample_executable.setTarget(target);
    server_sample_executable.install();

    const client_sample_executable = b.addExecutable("client", "samples/client.zig");
    client_sample_executable.addPackage(ztun_package);
    client_sample_executable.setBuildMode(mode);
    client_sample_executable.setTarget(target);
    client_sample_executable.install();

    const ztun_tests = b.addTest("src/ztun.zig");
    ztun_tests.setBuildMode(mode);

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
