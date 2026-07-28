//! CSPRNG helpers. Zig 0.16 has no `std.crypto.random` global -- real
//! randomness only comes from an `std.Io` instance, via
//! `std.Random.IoSource`.
const std = @import("std");
const Allocator = std.mem.Allocator;

const default_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A `std.Random` backed by the host's real CSPRNG, built from a
/// caller-owned `source`. `std.Random.IoSource.interface()` returns a
/// `std.Random` that holds a pointer back into `source` -- `source`
/// must outlive every use of the returned `std.Random`, so it can't be
/// a value local to a helper function (that would dangle the instant
/// the helper returned). Kept for callers who need a `std.Random` to
/// pass around explicitly; `randomBytesAlloc`/`randomInt`/
/// `randomString` below don't have this hazard because each builds and
/// fully consumes its own `IoSource` before returning.
pub fn csprng(source: *const std.Random.IoSource) std.Random {
    return source.interface();
}

/// Allocates and fills `n` cryptographically random bytes.
pub fn randomBytesAlloc(allocator: Allocator, io: std.Io, n: usize) ![]u8 {
    const buf = try allocator.alloc(u8, n);
    const source: std.Random.IoSource = .{ .io = io };
    source.interface().bytes(buf);
    return buf;
}

/// Unbiased random integer in `[min, max]`. `std.Random.intRangeAtMost`
/// already avoids modulo bias -- this is a thin pass-through so callers
/// don't need to build a `std.Random` themselves for one integer.
pub fn randomInt(io: std.Io, comptime T: type, min: T, max: T) T {
    const source: std.Random.IoSource = .{ .io = io };
    return source.interface().intRangeAtMost(T, min, max);
}

/// Allocates a random string of `len` characters drawn from `alphabet`
/// (default: alphanumeric) -- for tokens, API keys, short codes.
pub fn randomString(allocator: Allocator, io: std.Io, len: usize, alphabet: ?[]const u8) ![]u8 {
    const chars = alphabet orelse default_alphabet;
    std.debug.assert(chars.len > 0);

    const source: std.Random.IoSource = .{ .io = io };
    const random = source.interface();
    const buf = try allocator.alloc(u8, len);
    for (buf) |*c| {
        c.* = chars[random.uintLessThan(usize, chars.len)];
    }
    return buf;
}
