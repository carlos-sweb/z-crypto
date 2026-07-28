//! Compact JWS, HS256 only: base64url(header) + "." + base64url(payload)
//! + "." + base64url(HMAC-SHA256(signing_input, key)). `header_json`/
//! `payload_json` are ALREADY-SERIALIZED JSON the caller provides --
//! this module does the signing mechanics only, no claim semantics
//! (exp/iat/aud validation needs a JSON parser, which z-crypto
//! deliberately doesn't depend on). That's why this is `jws`, not `jwt`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const hmac = @import("hmac.zig");
const b64 = std.base64.url_safe_no_pad;

pub const SignError = Allocator.Error;
pub const VerifyError = error{ MalformedToken, InvalidSignature, OutOfMemory };

pub const Verified = struct {
    header_json: []u8,
    payload_json: []u8,

    pub fn deinit(self: Verified, allocator: Allocator) void {
        allocator.free(self.header_json);
        allocator.free(self.payload_json);
    }
};

/// Returns an allocator-owned compact JWS string.
pub fn sign(allocator: Allocator, header_json: []const u8, payload_json: []const u8, key: []const u8) SignError![]u8 {
    const header_b64_len = b64.Encoder.calcSize(header_json.len);
    const payload_b64_len = b64.Encoder.calcSize(payload_json.len);
    const sig_b64_len = comptime b64.Encoder.calcSize(32);

    // header_b64 + "." + payload_b64 + "." + sig_b64
    const signing_input_len = header_b64_len + 1 + payload_b64_len;
    const total_len = signing_input_len + 1 + sig_b64_len;

    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);

    _ = b64.Encoder.encode(out[0..header_b64_len], header_json);
    out[header_b64_len] = '.';
    _ = b64.Encoder.encode(out[header_b64_len + 1 ..][0..payload_b64_len], payload_json);
    out[signing_input_len] = '.';

    const mac = hmac.hmacSha256(key, out[0..signing_input_len]);
    _ = b64.Encoder.encode(out[signing_input_len + 1 ..][0..sig_b64_len], &mac);

    return out;
}

/// Splits `token` on '.', recomputes HMAC-SHA256 over the first two
/// segments, and compares against the third with
/// `std.crypto.timing_safe.eql` BEFORE decoding anything -- a forged
/// token is rejected without ever base64-decoding attacker-controlled
/// bytes as "trusted" JSON.
pub fn verify(allocator: Allocator, token: []const u8, key: []const u8) VerifyError!Verified {
    var it = std.mem.splitScalar(u8, token, '.');
    const header_b64 = it.next() orelse return error.MalformedToken;
    const payload_b64 = it.next() orelse return error.MalformedToken;
    const sig_b64 = it.next() orelse return error.MalformedToken;
    if (it.next() != null) return error.MalformedToken;

    const signing_input_len = header_b64.len + 1 + payload_b64.len;
    const signing_input = token[0..signing_input_len];

    const expected_mac = hmac.hmacSha256(key, signing_input);
    const sig_len = comptime b64.Encoder.calcSize(32);
    var expected_sig_buf: [sig_len]u8 = undefined;
    _ = b64.Encoder.encode(&expected_sig_buf, &expected_mac);

    if (sig_b64.len != sig_len) return error.InvalidSignature;
    var actual_sig_buf: [sig_len]u8 = undefined;
    @memcpy(&actual_sig_buf, sig_b64);

    if (!std.crypto.timing_safe.eql([sig_len]u8, expected_sig_buf, actual_sig_buf)) {
        return error.InvalidSignature;
    }

    const header_json = decodeAlloc(allocator, header_b64) catch return error.MalformedToken;
    errdefer allocator.free(header_json);
    const payload_json = decodeAlloc(allocator, payload_b64) catch return error.MalformedToken;
    errdefer allocator.free(payload_json);

    return .{ .header_json = header_json, .payload_json = payload_json };
}

fn decodeAlloc(allocator: Allocator, encoded: []const u8) ![]u8 {
    const len = try b64.Decoder.calcSizeForSlice(encoded);
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    try b64.Decoder.decode(out, encoded);
    return out;
}
