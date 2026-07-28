const std = @import("std");
const testing = std.testing;
const zcrypto = @import("zcrypto");
const base32 = zcrypto.base32;

// RFC 4648 SS10 test vectors.
const vectors = [_]struct { plain: []const u8, encoded: []const u8 }{
    .{ .plain = "", .encoded = "" },
    .{ .plain = "f", .encoded = "MY======" },
    .{ .plain = "fo", .encoded = "MZXQ====" },
    .{ .plain = "foo", .encoded = "MZXW6===" },
    .{ .plain = "foob", .encoded = "MZXW6YQ=" },
    .{ .plain = "fooba", .encoded = "MZXW6YTB" },
    .{ .plain = "foobar", .encoded = "MZXW6YTBOI======" },
};

test "encodeAlloc matches RFC 4648's test vectors" {
    for (vectors) |v| {
        const enc = try base32.encodeAlloc(testing.allocator, v.plain);
        defer testing.allocator.free(enc);
        try testing.expectEqualStrings(v.encoded, enc);
    }
}

test "decodeAlloc matches RFC 4648's test vectors" {
    for (vectors) |v| {
        const dec = try base32.decodeAlloc(testing.allocator, v.encoded);
        defer testing.allocator.free(dec);
        try testing.expectEqualStrings(v.plain, dec);
    }
}

test "decodeAlloc tolerates missing padding and lowercase" {
    const dec1 = try base32.decodeAlloc(testing.allocator, "MZXW6YQ");
    defer testing.allocator.free(dec1);
    try testing.expectEqualStrings("foob", dec1);

    const dec2 = try base32.decodeAlloc(testing.allocator, "mzxw6ytb");
    defer testing.allocator.free(dec2);
    try testing.expectEqualStrings("fooba", dec2);
}

test "decodeAlloc rejects an invalid character" {
    try testing.expectError(error.InvalidCharacter, base32.decodeAlloc(testing.allocator, "MZXW6Y!B"));
}

test "round-trip over arbitrary bytes" {
    var data: [37]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i * 7 + 3);

    const enc = try base32.encodeAlloc(testing.allocator, &data);
    defer testing.allocator.free(enc);
    const dec = try base32.decodeAlloc(testing.allocator, enc);
    defer testing.allocator.free(dec);
    try testing.expectEqualSlices(u8, &data, dec);
}
