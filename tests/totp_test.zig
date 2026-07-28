const std = @import("std");
const testing = std.testing;
const zcrypto = @import("zcrypto");
const totp = zcrypto.totp;

// RFC 4226 Appendix D's secret, used by RFC 6238's test vectors too.
const secret = "12345678901234567890";

test "hotp matches RFC 4226 Appendix D's 10 vectors" {
    const expected = [_][]const u8{
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489",
    };
    var buf: [6]u8 = undefined;
    for (expected, 0..) |exp, i| {
        const code = totp.hotp(secret, i, 6, &buf);
        try testing.expectEqualStrings(exp, code);
    }
}

test "totp matches RFC 6238 Appendix B's 8-digit SHA1 vectors" {
    const cases = [_]struct { time: i64, code: []const u8 }{
        .{ .time = 59, .code = "94287082" },
        .{ .time = 1111111109, .code = "07081804" },
        .{ .time = 1111111111, .code = "14050471" },
        .{ .time = 1234567890, .code = "89005924" },
        .{ .time = 2000000000, .code = "69279037" },
        .{ .time = 20000000000, .code = "65353130" },
    };
    var buf: [8]u8 = undefined;
    for (cases) |c| {
        const code = totp.totp(secret, c.time, 30, 8, &buf);
        try testing.expectEqualStrings(c.code, code);
    }
}

test "hotp zero-pads short codes instead of truncating them" {
    // Find a counter whose HOTP happens to start with a zero digit, to
    // prove leading zeros survive (a bare-integer formatting would drop
    // them). Bounded search over a small, deterministic range.
    var buf: [6]u8 = undefined;
    var counter: u64 = 0;
    var found = false;
    while (counter < 1000) : (counter += 1) {
        const code = totp.hotp(secret, counter, 6, &buf);
        if (code[0] == '0') {
            found = true;
            try testing.expectEqual(@as(usize, 6), code.len);
            break;
        }
    }
    try testing.expect(found);
}

test "verifyTotp accepts the exact step and rejects a wrong code" {
    try testing.expect(totp.verifyTotp(secret, "94287082", 59, 30, 8, 0));
    try testing.expect(!totp.verifyTotp(secret, "00000000", 59, 30, 8, 0));
}

test "verifyTotp honors the window for clock drift, rejects outside it" {
    const one_step_later = 59 + 30;
    // Exact-step-only (window 0): the previous step's code must fail.
    try testing.expect(!totp.verifyTotp(secret, "94287082", one_step_later, 30, 8, 0));
    // window 1: one step back is accepted.
    try testing.expect(totp.verifyTotp(secret, "94287082", one_step_later, 30, 8, 1));
    // Two steps away is still rejected even with window 1.
    const two_steps_later = 59 + 60;
    try testing.expect(!totp.verifyTotp(secret, "94287082", two_steps_later, 30, 8, 1));
}
