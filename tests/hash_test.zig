const std = @import("std");
const testing = std.testing;
const zcrypto = @import("zcrypto");
const hash = zcrypto.hash;

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "sha256(\"abc\") matches the NIST known-answer vector" {
    const expected = hexToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    try testing.expectEqualSlices(u8, &expected, &hash.sha256("abc"));
}

test "sha512(\"abc\") matches the NIST known-answer vector" {
    const expected = hexToBytes("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39" ++
        "a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    try testing.expectEqualSlices(u8, &expected, &hash.sha512("abc"));
}

test "blake3(\"\") matches the reference empty-input digest" {
    const expected = hexToBytes("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    try testing.expectEqualSlices(u8, &expected, &hash.blake3(""));
}

test "generic hash() dispatch matches the typed functions" {
    const data = "the quick brown fox";

    var out256: [32]u8 = undefined;
    hash.hash(.sha256, data, &out256);
    try testing.expectEqualSlices(u8, &hash.sha256(data), &out256);

    var out512: [64]u8 = undefined;
    hash.hash(.sha512, data, &out512);
    try testing.expectEqualSlices(u8, &hash.sha512(data), &out512);

    var outb3: [32]u8 = undefined;
    hash.hash(.blake3, data, &outb3);
    try testing.expectEqualSlices(u8, &hash.blake3(data), &outb3);
}

test "digestLength matches each algorithm's real output size" {
    try testing.expectEqual(@as(usize, 32), hash.digestLength(.sha256));
    try testing.expectEqual(@as(usize, 64), hash.digestLength(.sha512));
    try testing.expectEqual(@as(usize, 32), hash.digestLength(.blake3));
}
