// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn build(b: *std.Build) !void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const install_tests = b.option(bool, "install_tests", "Install tests exe during install step") orelse false;
    const build_samples = b.option(bool, "build_samples", "Build and install samples exes") orelse false;

    // Modules available to downstream dependencies
    const ztun_module = b.addModule("ztun", .{
        .source_file = .{ .path = "src/ztun.zig" },
    });

    if (build_samples) {
        const path = try b.build_root.join(b.allocator, &[_][]const u8{"samples"});
        const dir = try std.fs.openDirAbsolute(path, std.fs.Dir.OpenDirOptions{ .iterate = true });
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            const extension = std.fs.path.extension(entry.name);
            if (!std.mem.eql(u8, extension, ".zig")) continue;

            const sample_name = std.fs.path.stem(entry.name);
            const source_file_path = try std.fs.path.join(b.allocator, &.{ path, entry.name });

            const sample_exe = b.addExecutable(.{
                .name = sample_name,
                .root_source_file = .{ .path = source_file_path },
                .optimize = optimize,
                .target = target,
            });
            sample_exe.addModule("ztun", ztun_module);
            sample_exe.linkLibC();

            b.installArtifact(sample_exe);
        }
    }

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
