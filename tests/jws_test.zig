const std = @import("std");
const testing = std.testing;
const zcrypto = @import("zcrypto");
const jws = zcrypto.jws;

const header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
const payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}";
const key = "secret-key";

test "sign -> verify round-trips the exact header/payload bytes" {
    const token = try jws.sign(testing.allocator, header, payload, key);
    defer testing.allocator.free(token);

    const verified = try jws.verify(testing.allocator, token, key);
    defer verified.deinit(testing.allocator);

    try testing.expectEqualStrings(header, verified.header_json);
    try testing.expectEqualStrings(payload, verified.payload_json);
}

test "token has the standard three-segment compact JWS shape" {
    const token = try jws.sign(testing.allocator, header, payload, key);
    defer testing.allocator.free(token);

    var it = std.mem.splitScalar(u8, token, '.');
    _ = it.next().?;
    _ = it.next().?;
    _ = it.next().?;
    try testing.expect(it.next() == null);
}

test "verify rejects a token signed with a different key" {
    const token = try jws.sign(testing.allocator, header, payload, key);
    defer testing.allocator.free(token);

    try testing.expectError(error.InvalidSignature, jws.verify(testing.allocator, token, "wrong-key"));
}

test "verify rejects a tampered signature" {
    const token = try jws.sign(testing.allocator, header, payload, key);
    defer testing.allocator.free(token);

    const tampered = try testing.allocator.dupe(u8, token);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] = if (tampered[tampered.len - 1] == 'A') 'B' else 'A';

    try testing.expectError(error.InvalidSignature, jws.verify(testing.allocator, tampered, key));
}

test "verify rejects a tampered payload" {
    const token = try jws.sign(testing.allocator, header, payload, key);
    defer testing.allocator.free(token);

    const tampered = try testing.allocator.dupe(u8, token);
    defer testing.allocator.free(tampered);
    // Flip a character inside the payload segment (between the two dots).
    const first_dot = std.mem.indexOfScalar(u8, tampered, '.').?;
    tampered[first_dot + 1] = if (tampered[first_dot + 1] == 'A') 'B' else 'A';

    try testing.expectError(error.InvalidSignature, jws.verify(testing.allocator, tampered, key));
}

test "verify rejects a malformed (wrong segment count) token" {
    try testing.expectError(error.MalformedToken, jws.verify(testing.allocator, "not.enough", key));
    try testing.expectError(error.MalformedToken, jws.verify(testing.allocator, "a.b.c.d", key));
    try testing.expectError(error.MalformedToken, jws.verify(testing.allocator, "nodotsatall", key));
}

test "two signatures for the same input with the same key match" {
    const token1 = try jws.sign(testing.allocator, header, payload, key);
    defer testing.allocator.free(token1);
    const token2 = try jws.sign(testing.allocator, header, payload, key);
    defer testing.allocator.free(token2);

    try testing.expectEqualStrings(token1, token2);
}
