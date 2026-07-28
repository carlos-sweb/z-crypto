//! `z-crypto`: thin, ergonomic wrappers over `std.crypto` -- CSPRNG,
//! hashing, HMAC, AEAD, Argon2id password hashing, base32, TOTP/HOTP,
//! and compact JWS (HS256).
pub const random = @import("random.zig");
pub const hash = @import("hash.zig");
pub const hmac = @import("hmac.zig");
pub const aead = @import("aead.zig");
pub const password = @import("password.zig");
pub const base32 = @import("base32.zig");
pub const totp = @import("totp.zig");
pub const jws = @import("jws.zig");

test {
    _ = @import("random.zig");
    _ = @import("hash.zig");
    _ = @import("hmac.zig");
    _ = @import("aead.zig");
    _ = @import("password.zig");
    _ = @import("base32.zig");
    _ = @import("totp.zig");
    _ = @import("jws.zig");
}
