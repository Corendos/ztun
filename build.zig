// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const version = std.SemanticVersion{
    .major = 0,
    .minor = 0,
    .patch = 2,
};

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("ztun", "src/ztun.zig");
    lib.setBuildMode(mode);
    lib.setTarget(target);
    lib.install();

    const executable = b.addExecutable("main", "src/main.zig");
    executable.setBuildMode(mode);
    executable.setTarget(target);
    executable.install();

    const exe_options = b.addOptions();
    executable.addOptions("build_options", exe_options);
    exe_options.addOption(std.SemanticVersion, "version", version);

    const ztun_tests = b.addTest("src/ztun.zig");
    ztun_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&ztun_tests.step);

    const exe_run_step = executable.run();
    exe_run_step.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run main program");
    run_step.dependOn(&exe_run_step.step);
}
