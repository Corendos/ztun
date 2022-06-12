const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("ztun", "src/main.zig");
    lib.setBuildMode(mode);
    lib.install();

    const main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);

    const sample_exe = b.addExecutable("sample", "src/sample.zig");
    sample_exe.setBuildMode(mode);
    sample_exe.install();


    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const sample_run_cmd = sample_exe.run();
    sample_run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("sample", "Run the sample");
    run_step.dependOn(&sample_run_cmd.step);
}
