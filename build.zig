// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const Step = std.Build.Step;

pub fn build(b: *std.Build) !void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const install_tests = b.option(bool, "install_tests", "Install tests exe during install step") orelse false;
    const build_samples = b.option(bool, "build_samples", "Build and install samples exes") orelse false;

    // Modules available to downstream dependencies
    _ = b.addModule("ztun", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/ztun.zig"),
    });

    const samples = try buildSamples(b, target, optimize);

    const ztun_tests = b.addTest(.{
        .root_source_file = b.path("src/ztun.zig"),
        .target = target,
        .optimize = optimize,
    });
    const ztun_tests_run = b.addRunArtifact(ztun_tests);
    if (install_tests) b.installArtifact(ztun_tests);

    if (build_samples) for (samples) |sample| {
        b.getInstallStep().dependOn(&b.addInstallArtifact(sample, .{}).step);
    };

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&ztun_tests_run.step);
}

fn buildSamples(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) ![]const *Step.Compile {
    var steps = std.ArrayList(*Step.Compile).init(b.allocator);
    defer steps.deinit();

    const path = try b.build_root.join(b.allocator, &[_][]const u8{"samples"});
    var dir = try std.fs.cwd().openDir(path, .{ .iterate = true});
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        const extension = std.fs.path.extension(entry.name);
        if (!std.mem.eql(u8, extension, ".zig")) continue;

        const sample_name = std.fs.path.stem(entry.name);

        const sample_exe = b.addExecutable(.{
            .name = sample_name,
            .root_source_file = b.path(b.fmt("samples/{s}", .{entry.name})),
            .optimize = optimize,
            .target = target,
        });
        sample_exe.root_module.addImport("ztun", b.modules.get("ztun").?);
        sample_exe.linkLibC();

        try steps.append(sample_exe);
    }

    return steps.toOwnedSlice();
}
