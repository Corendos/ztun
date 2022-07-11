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

    const client_sample_exe = b.addExecutable("client_sample", "src/client_sample.zig");
    client_sample_exe.setBuildMode(mode);
    client_sample_exe.install();

    const server_sample_exe = b.addExecutable("server_sample", "src/server_sample.zig");
    server_sample_exe.setBuildMode(mode);
    server_sample_exe.install();

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const client_sample_run_cmd = client_sample_exe.run();
    client_sample_run_cmd.step.dependOn(b.getInstallStep());

    const client_sample_run_step = b.step("client", "Run the client sample");
    client_sample_run_step.dependOn(&client_sample_run_cmd.step);

    const server_sample_run_cmd = server_sample_exe.run();
    server_sample_run_cmd.step.dependOn(b.getInstallStep());

    const server_sample_run_step = b.step("server", "Run the server sample");
    server_sample_run_step.dependOn(&server_sample_run_cmd.step);
}
