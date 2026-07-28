//! HMAC-SHA1 / HMAC-SHA256 / HMAC-SHA512.
const std = @import("std");

/// SHA-1 itself is excluded from this library as a general-purpose hash
/// (collision resistance is broken -- see plan.md's exclusion list).
/// HMAC doesn't share that weakness: its security doesn't depend on the
/// inner hash's collision resistance the way content-integrity hashing
/// or signatures do, which is why HMAC-SHA1 remains standardized for
/// MACs/KDFs (PBKDF2-HMAC-SHA1, TLS 1.2) -- and is specifically what RFC
/// 4226/6238 TOTP/HOTP mandates, matching every real authenticator app.
pub fn hmacSha1(key: []const u8, data: []const u8) [20]u8 {
    var out: [20]u8 = undefined;
    std.crypto.auth.hmac.HmacSha1.create(&out, data, key);
    return out;
}

pub fn hmacSha256(key: []const u8, data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, data, key);
    return out;
}

pub fn hmacSha512(key: []const u8, data: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&out, data, key);
    return out;
}
