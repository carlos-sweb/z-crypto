//! Authenticated encryption: XChaCha20-Poly1305. Encrypt returns a single
//! self-describing blob (`nonce || ciphertext || tag`) so callers don't
//! have to juggle the nonce separately -- combined mode, like libsodium's
//! `crypto_secretbox`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Cipher = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const key_length = Cipher.key_length; // 32
pub const nonce_length = Cipher.nonce_length; // 24
pub const tag_length = Cipher.tag_length; // 16

pub const DecryptError = error{
    OutOfMemory,
    AuthenticationFailed,
    InvalidBlob,
};

/// Encrypts `plaintext`, authenticating `aad` alongside it. The nonce is
/// drawn fresh from `io`'s CSPRNG on every call.
pub fn encrypt(
    allocator: Allocator,
    io: std.Io,
    key: [key_length]u8,
    plaintext: []const u8,
    aad: []const u8,
) Allocator.Error![]u8 {
    const blob = try allocator.alloc(u8, nonce_length + plaintext.len + tag_length);
    errdefer allocator.free(blob);

    const nonce = blob[0..nonce_length];
    const ciphertext = blob[nonce_length .. nonce_length + plaintext.len];
    const tag = blob[nonce_length + plaintext.len ..][0..tag_length];

    const random_source: std.Random.IoSource = .{ .io = io };
    random_source.interface().bytes(nonce);

    Cipher.encrypt(ciphertext, tag, plaintext, aad, nonce.*, key);
    return blob;
}

/// Decrypts a blob produced by `encrypt`. `error.AuthenticationFailed` on
/// a wrong key, wrong `aad`, or any tampering; `error.InvalidBlob` if the
/// blob is too short to even contain a nonce and tag.
pub fn decrypt(
    allocator: Allocator,
    key: [key_length]u8,
    blob: []const u8,
    aad: []const u8,
) DecryptError![]u8 {
    if (blob.len < nonce_length + tag_length) return error.InvalidBlob;

    const nonce = blob[0..nonce_length];
    const ciphertext = blob[nonce_length .. blob.len - tag_length];
    const tag = blob[blob.len - tag_length ..];

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    Cipher.decrypt(plaintext, ciphertext, tag[0..tag_length].*, aad, nonce.*, key) catch {
        return error.AuthenticationFailed;
    };
    return plaintext;
}
