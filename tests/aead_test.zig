const std = @import("std");
const testing = std.testing;
const zcrypto = @import("zcrypto");
const aead = zcrypto.aead;

const key: [aead.key_length]u8 = [_]u8{0x42} ** aead.key_length;
const other_key: [aead.key_length]u8 = [_]u8{0x24} ** aead.key_length;

test "round-trip: decrypt(encrypt(m)) == m" {
    const plaintext = "attack at dawn";
    const aad = "header";

    const blob = try aead.encrypt(testing.allocator, testing.io, key, plaintext, aad);
    defer testing.allocator.free(blob);

    const decrypted = try aead.decrypt(testing.allocator, key, blob, aad);
    defer testing.allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "decrypt fails with the wrong key" {
    const blob = try aead.encrypt(testing.allocator, testing.io, key, "secret", "");
    defer testing.allocator.free(blob);

    try testing.expectError(error.AuthenticationFailed, aead.decrypt(testing.allocator, other_key, blob, ""));
}

test "decrypt fails with the wrong aad" {
    const blob = try aead.encrypt(testing.allocator, testing.io, key, "secret", "right-aad");
    defer testing.allocator.free(blob);

    try testing.expectError(error.AuthenticationFailed, aead.decrypt(testing.allocator, key, blob, "wrong-aad"));
}

test "decrypt fails when the ciphertext is tampered with" {
    const blob = try aead.encrypt(testing.allocator, testing.io, key, "secret message", "");
    defer testing.allocator.free(blob);

    blob[blob.len - aead.tag_length - 1] ^= 0xFF;
    try testing.expectError(error.AuthenticationFailed, aead.decrypt(testing.allocator, key, blob, ""));
}

test "decrypt rejects a blob too short to hold a nonce and tag" {
    const too_short = [_]u8{0} ** (aead.nonce_length + aead.tag_length - 1);
    try testing.expectError(error.InvalidBlob, aead.decrypt(testing.allocator, key, &too_short, ""));
}

test "two encryptions of the same plaintext produce different blobs (fresh nonce)" {
    const blob1 = try aead.encrypt(testing.allocator, testing.io, key, "same plaintext", "");
    defer testing.allocator.free(blob1);
    const blob2 = try aead.encrypt(testing.allocator, testing.io, key, "same plaintext", "");
    defer testing.allocator.free(blob2);

    try testing.expect(!std.mem.eql(u8, blob1, blob2));
}

test "encrypting empty plaintext round-trips to an empty result" {
    const blob = try aead.encrypt(testing.allocator, testing.io, key, "", "");
    defer testing.allocator.free(blob);

    const decrypted = try aead.decrypt(testing.allocator, key, blob, "");
    defer testing.allocator.free(decrypted);

    try testing.expectEqual(@as(usize, 0), decrypted.len);
}
