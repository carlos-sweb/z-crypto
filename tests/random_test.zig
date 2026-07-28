const std = @import("std");
const testing = std.testing;
const zcrypto = @import("zcrypto");
const random = zcrypto.random;

test "randomBytesAlloc returns the requested length and isn't all-zero" {
    const bytes = try random.randomBytesAlloc(testing.allocator, testing.io, 64);
    defer testing.allocator.free(bytes);

    try testing.expectEqual(@as(usize, 64), bytes.len);

    var all_zero = true;
    for (bytes) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "randomInt never leaves [min, max]" {
    for (0..200) |_| {
        const n = random.randomInt(testing.io, i32, -10, 10);
        try testing.expect(n >= -10 and n <= 10);
    }
}

test "randomString only contains characters from the given alphabet" {
    const alphabet = "01";
    const s = try random.randomString(testing.allocator, testing.io, 100, alphabet);
    defer testing.allocator.free(s);

    try testing.expectEqual(@as(usize, 100), s.len);
    for (s) |c| {
        try testing.expect(c == '0' or c == '1');
    }
}

test "randomString defaults to an alphanumeric alphabet" {
    const s = try random.randomString(testing.allocator, testing.io, 40, null);
    defer testing.allocator.free(s);

    for (s) |c| {
        try testing.expect(std.ascii.isAlphanumeric(c));
    }
}

test "csprng(source) works when source is kept alive by the caller" {
    const source: std.Random.IoSource = .{ .io = testing.io };
    const r = random.csprng(&source);
    var buf: [8]u8 = undefined;
    r.bytes(&buf);
}

test "two calls to csprng-backed randomness produce different output" {
    const a = try random.randomBytesAlloc(testing.allocator, testing.io, 32);
    defer testing.allocator.free(a);
    const b = try random.randomBytesAlloc(testing.allocator, testing.io, 32);
    defer testing.allocator.free(b);

    try testing.expect(!std.mem.eql(u8, a, b));
}
