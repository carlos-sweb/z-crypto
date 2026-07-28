const std = @import("std");
const testing = std.testing;
const zcrypto = @import("zcrypto");
const password = zcrypto.password;

test "hash -> verify succeeds for the right password" {
    const phc = try password.hash(testing.allocator, testing.io, "correct horse battery staple");
    defer testing.allocator.free(phc);

    const ok = try password.verify(testing.allocator, testing.io, phc, "correct horse battery staple");
    try testing.expect(ok);
}

test "verify returns false for the wrong password" {
    const phc = try password.hash(testing.allocator, testing.io, "correct horse battery staple");
    defer testing.allocator.free(phc);

    const ok = try password.verify(testing.allocator, testing.io, phc, "wrong password");
    try testing.expect(!ok);
}

test "hash output is a PHC-formatted string starting with $argon2id$" {
    const phc = try password.hash(testing.allocator, testing.io, "hunter2");
    defer testing.allocator.free(phc);

    try testing.expect(std.mem.startsWith(u8, phc, "$argon2id$"));
}

test "hashing the same password twice yields different strings (fresh salt)" {
    const phc1 = try password.hash(testing.allocator, testing.io, "hunter2");
    defer testing.allocator.free(phc1);
    const phc2 = try password.hash(testing.allocator, testing.io, "hunter2");
    defer testing.allocator.free(phc2);

    try testing.expect(!std.mem.eql(u8, phc1, phc2));
}

test "verify rejects a malformed hash string instead of crashing" {
    try testing.expectError(error.InvalidEncoding, password.verify(testing.allocator, testing.io, "not-a-real-phc-string", "hunter2"));
}
