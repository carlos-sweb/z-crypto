//! RFC 4648 base32, uppercase alphabet (`A-Z2-7`) -- how TOTP secrets are
//! distributed for QR codes and manual entry (e.g. `JBSWY3DPEHPK3PXP`).
const std = @import("std");
const Allocator = std.mem.Allocator;

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub const DecodeError = error{InvalidCharacter};

/// Encodes `data`, padding the output to a multiple of 8 characters with
/// `=` (the RFC 4648 standard form).
pub fn encodeAlloc(allocator: Allocator, data: []const u8) ![]u8 {
    if (data.len == 0) return allocator.alloc(u8, 0);

    const out_len = ((data.len + 4) / 5) * 8;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    @memset(out, '=');

    var bit_buf: u64 = 0;
    var bits: u6 = 0;
    var out_idx: usize = 0;
    for (data) |byte| {
        bit_buf = (bit_buf << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            const idx: u5 = @truncate((bit_buf >> bits) & 0x1F);
            out[out_idx] = alphabet[idx];
            out_idx += 1;
        }
    }
    if (bits > 0) {
        const idx: u5 = @truncate((bit_buf << (5 - bits)) & 0x1F);
        out[out_idx] = alphabet[idx];
        out_idx += 1;
    }
    return out;
}

fn decodeChar(c: u8) DecodeError!u5 {
    return switch (c) {
        'A'...'Z' => @intCast(c - 'A'),
        'a'...'z' => @intCast(c - 'a'),
        '2'...'7' => @intCast(c - '2' + 26),
        else => error.InvalidCharacter,
    };
}

/// Decodes `encoded`, tolerant of missing `=` padding (real-world
/// secrets are usually shown unpadded) and of lowercase input.
pub fn decodeAlloc(allocator: Allocator, encoded: []const u8) ![]u8 {
    const trimmed = std.mem.trimEnd(u8, encoded, "=");
    if (trimmed.len == 0) return allocator.alloc(u8, 0);

    const out_len = (trimmed.len * 5) / 8;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    var bit_buf: u64 = 0;
    var bits: u6 = 0;
    var out_idx: usize = 0;
    for (trimmed) |c| {
        const val = try decodeChar(c);
        bit_buf = (bit_buf << 5) | val;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[out_idx] = @truncate((bit_buf >> bits) & 0xFF);
            out_idx += 1;
        }
    }
    return out;
}
