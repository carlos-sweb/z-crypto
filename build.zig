const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zcrypto_module = b.addModule("zcrypto", .{
        .root_source_file = b.path("src/zcrypto.zig"),
    });

    const test_step = b.step("test", "Run all tests");

    const test_files = [_][]const u8{
        "tests/random_test.zig",
        "tests/hash_test.zig",
        "tests/hmac_test.zig",
        "tests/aead_test.zig",
        "tests/password_test.zig",
        "tests/base32_test.zig",
        "tests/totp_test.zig",
        "tests/jws_test.zig",
    };

    inline for (test_files) |test_file| {
        const unit_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_file),
                .target = target,
                .optimize = optimize,
            }),
        });
        unit_tests.root_module.addImport("zcrypto", zcrypto_module);
        const run_unit_tests = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run_unit_tests.step);
    }

    b.default_step = test_step;
}
