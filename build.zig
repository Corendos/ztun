// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    // Modules available to downstream dependencies
    _ = b.addModule("ztun", .{
        .source_file = .{ .path = "/src/ztun.zig" },
    });

    const install_tests = b.option(bool, "install_tests", "Install tests exe during install step") orelse false;

    const ztun_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/ztun.zig" },
        .target = target,
        .optimize = optimize,
    });
    const ztun_tests_run = b.addRunArtifact(ztun_tests);
    if (install_tests) b.installArtifact(ztun_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&ztun_tests_run.step);
}
