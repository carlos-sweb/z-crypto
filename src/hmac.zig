//! HMAC-SHA256 / HMAC-SHA512.
const std = @import("std");

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
