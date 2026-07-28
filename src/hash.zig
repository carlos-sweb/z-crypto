//! Hashing: SHA-256, SHA-512, BLAKE3 -- typed helpers plus a runtime-
//! dispatchable `Algorithm` enum for callers (like a future scripting
//! binding) that can't pick a comptime function.
const std = @import("std");

pub fn sha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

pub fn sha512(data: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(data, &out, .{});
    return out;
}

pub fn blake3(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(data, &out, .{});
    return out;
}

pub const Algorithm = enum { sha256, sha512, blake3 };

pub fn digestLength(alg: Algorithm) usize {
    return switch (alg) {
        .sha256 => 32,
        .sha512 => 64,
        .blake3 => 32,
    };
}

/// Runtime-dispatched hash. `out.len` must equal `digestLength(alg)`.
pub fn hash(alg: Algorithm, data: []const u8, out: []u8) void {
    std.debug.assert(out.len == digestLength(alg));
    switch (alg) {
        .sha256 => std.crypto.hash.sha2.Sha256.hash(data, out[0..32], .{}),
        .sha512 => std.crypto.hash.sha2.Sha512.hash(data, out[0..64], .{}),
        .blake3 => std.crypto.hash.Blake3.hash(data, out[0..32], .{}),
    }
}
