// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn module(b: *std.Build) *std.Build.Module {
    return b.createModule(std.Build.CreateModuleOptions{
        .source_file = .{ .path = thisDir() ++ "/src/ztun.zig" },
    });
}

pub fn build(b: *std.Build) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const install_tests = b.option(bool, "install_tests", "Install tests exe during install step") orelse false;

    const ztun_tests = b.addTest(.{
        .root_source_file = std.Build.FileSource.relative("src/ztun.zig"),
        .target = target,
        .optimize = mode,
    });
    const ztun_tests_run = b.addRunArtifact(ztun_tests);
    if (install_tests) b.installArtifact(ztun_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&ztun_tests_run.step);
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
