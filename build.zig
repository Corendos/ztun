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
    const module = b.addModule("ztun", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/ztun.zig"),
    });

    const samples = try buildSamples(b, target, optimize);

    const ztun_tests = b.addTest(.{
        .root_module = module,
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
    var steps: std.ArrayList(*Step.Compile) = .empty;
    defer steps.deinit(b.allocator);

    const samples = [_][]const u8{
        "long_term_client.zig",
        "long_term_server.zig",
        "short_term_client.zig",
        "short_term_server.zig",
        "simple_client.zig",
        "simple_server.zig",
    };

    for (samples) |sample| {
        const sample_name = std.fs.path.stem(sample);

        const sample_path = try std.fs.path.join(b.allocator, &.{ "samples", sample });

        const sample_module = b.addModule(sample_name, .{
            .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = sample_path } },
            .optimize = optimize,
            .target = target,
        });

        const sample_exe = b.addExecutable(.{
            .name = sample_name,
            .root_module = sample_module,
        });
        sample_exe.root_module.addImport("ztun", b.modules.get("ztun").?);

        try steps.append(b.allocator, sample_exe);
    }

    return steps.toOwnedSlice(b.allocator);
}
