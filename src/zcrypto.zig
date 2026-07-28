//! `z-crypto`: thin, ergonomic wrappers over `std.crypto` -- CSPRNG,
//! hashing, HMAC, AEAD, and Argon2id password hashing.
pub const random = @import("random.zig");
pub const hash = @import("hash.zig");
pub const hmac = @import("hmac.zig");
pub const aead = @import("aead.zig");
pub const password = @import("password.zig");

test {
    _ = @import("random.zig");
    _ = @import("hash.zig");
    _ = @import("hmac.zig");
    _ = @import("aead.zig");
    _ = @import("password.zig");
}
