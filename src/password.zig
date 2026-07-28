//! Password hashing via Argon2id, using std's own OWASP-recommended
//! default parameters (`Params.owasp_2id`) -- no knobs to get wrong for
//! an MVP. Output is a self-contained PHC-formatted string (algorithm,
//! params, salt and hash all encoded together), so `verify` needs
//! nothing but the string and the candidate password.
const std = @import("std");
const Allocator = std.mem.Allocator;
const argon2 = std.crypto.pwhash.argon2;

// PHC strings for owasp_2id (32-byte salt, 32-byte hash) are well under
// 100 bytes; 128 leaves ample margin without risking a runtime failure.
const phc_buf_len = 128;

pub const HashError = std.crypto.pwhash.Error || Allocator.Error;
pub const VerifyError = error{ InvalidEncoding, OutOfMemory };

/// Hashes `password`, returning an allocator-owned PHC string. The salt
/// is drawn fresh from `io`'s CSPRNG internally by `std.crypto.pwhash`.
pub fn hash(allocator: Allocator, io: std.Io, password: []const u8) HashError![]u8 {
    var buf: [phc_buf_len]u8 = undefined;
    const phc = try argon2.strHash(password, .{
        .allocator = allocator,
        .params = argon2.Params.owasp_2id,
        .mode = .argon2id,
    }, &buf, io);
    return allocator.dupe(u8, phc);
}

/// Checks `password` against a PHC string produced by `hash`. Returns
/// `false` for a wrong password, an error only for a malformed string or
/// allocation failure -- so a bad password never crashes the caller.
pub fn verify(allocator: Allocator, io: std.Io, phc_str: []const u8, password: []const u8) VerifyError!bool {
    argon2.strVerify(phc_str, password, .{ .allocator = allocator }, io) catch |err| switch (err) {
        error.PasswordVerificationFailed => return false,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidEncoding,
    };
    return true;
}
