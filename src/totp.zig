//! HOTP (RFC 4226) and TOTP (RFC 6238) one-time passwords, HMAC-SHA1 as
//! both RFCs mandate -- see hmac.zig's doc comment for why that's a
//! different security property than the excluded raw-SHA1 hash.
const std = @import("std");
const hmac = @import("hmac.zig");

const pow10 = [_]u32{ 1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000 };

/// HOTP (RFC 4226 SS5.3). `secret` is the raw (already base32-decoded)
/// key. `digits` is typically 6 (RFC default) or 8. Writes the
/// zero-padded decimal code into `buf` (must be >= digits long) and
/// returns the written slice.
pub fn hotp(secret: []const u8, counter: u64, digits: u8, buf: []u8) []const u8 {
    std.debug.assert(digits >= 1 and digits <= 9);
    std.debug.assert(buf.len >= digits);

    var counter_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter_bytes, counter, .big);

    const mac = hmac.hmacSha1(secret, &counter_bytes);

    const offset: usize = mac[19] & 0x0F;
    const p = (@as(u32, mac[offset] & 0x7F) << 24) |
        (@as(u32, mac[offset + 1]) << 16) |
        (@as(u32, mac[offset + 2]) << 8) |
        @as(u32, mac[offset + 3]);

    var code = p % pow10[digits];
    var i: usize = digits;
    while (i > 0) {
        i -= 1;
        buf[i] = @as(u8, @intCast(code % 10)) + '0';
        code /= 10;
    }
    return buf[0..digits];
}

/// TOTP (RFC 6238): `unix_time`/`step_seconds` (default step 30) select
/// the counter fed to `hotp`.
pub fn totp(secret: []const u8, unix_time: i64, step_seconds: u64, digits: u8, buf: []u8) []const u8 {
    const counter: u64 = @intCast(@divFloor(unix_time, @as(i64, @intCast(step_seconds))));
    return hotp(secret, counter, digits, buf);
}

/// Same as `totp`, reading the current time from `io` instead of a
/// caller-supplied timestamp -- same `std.Io.Clock.real` pattern
/// `z-uuid`'s `v7` uses (Zig 0.16 has no `std.time.milliTimestamp`
/// global).
pub fn totpNow(secret: []const u8, io: std.Io, step_seconds: u64, digits: u8, buf: []u8) []const u8 {
    const ts = std.Io.Clock.real.now(io);
    const unix_s: i64 = @intCast(@divFloor(ts.nanoseconds, std.time.ns_per_s));
    return totp(secret, unix_s, step_seconds, digits, buf);
}

/// Verifies `code` against TOTP values in a `+/- window` step tolerance
/// around `unix_time` (clock drift forgiveness). `window = 0` means
/// exact-step-only.
pub fn verifyTotp(secret: []const u8, code: []const u8, unix_time: i64, step_seconds: u64, digits: u8, window: u32) bool {
    if (code.len != digits) return false;

    const step: i64 = @intCast(step_seconds);
    const w: i64 = @intCast(window);
    var buf: [9]u8 = undefined;

    var offset: i64 = -w;
    while (offset <= w) : (offset += 1) {
        const candidate_time = unix_time + offset * step;
        const candidate = totp(secret, candidate_time, step_seconds, digits, buf[0..digits]);
        if (std.mem.eql(u8, candidate, code)) return true;
    }
    return false;
}
