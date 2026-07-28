const std = @import("std");
const testing = std.testing;
const zcrypto = @import("zcrypto");
const hmac = zcrypto.hmac;

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// RFC 4231 test case 1: key = 20 bytes of 0x0b, data = "Hi There".
const rfc_key = [_]u8{0x0b} ** 20;
const rfc_data = "Hi There";

test "hmacSha256 matches RFC 4231 test case 1" {
    const expected = hexToBytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    try testing.expectEqualSlices(u8, &expected, &hmac.hmacSha256(&rfc_key, rfc_data));
}

test "hmacSha512 matches RFC 4231 test case 1" {
    const expected = hexToBytes("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd" ++
        "edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    try testing.expectEqualSlices(u8, &expected, &hmac.hmacSha512(&rfc_key, rfc_data));
}

test "different keys produce different MACs for the same data" {
    const mac1 = hmac.hmacSha256("key-one", "same data");
    const mac2 = hmac.hmacSha256("key-two", "same data");
    try testing.expect(!std.mem.eql(u8, &mac1, &mac2));
}
