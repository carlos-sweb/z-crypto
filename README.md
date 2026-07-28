# z-crypto

Thin, ergonomic wrappers over `std.crypto` — CSPRNG, hashing, HMAC,
authenticated encryption, and Argon2id password hashing. Pure Zig, zero
dependencies beyond `std`.

## Why a wrapper at all

`std.crypto` in Zig 0.16 is already comprehensive (it even ships
post-quantum ML-KEM/ML-DSA), but it's a toolbox, not an API: every
primitive lives in its own namespace with its own type-level shape, and
Zig 0.16 routes real randomness/time through `std.Io` rather than a
global (`std.crypto.random`/`std.time.milliTimestamp` don't exist
anymore). `z-crypto` picks one good default per common task and gives it
a short, consistent name, so callers don't have to rediscover
`std.Random.IoSource` or pick an Argon2 memory-cost parameter themselves.

Full feature research (with `std.crypto` coverage annotated, and a
deliberate exclusion list for MD5/SHA-1/DES/3DES/RC4/ECB) lives in
[`plan.md`](./plan.md).

## Dependency

```zig
// build.zig.zon
.dependencies = .{
    .zcrypto = .{ .path = "../z-crypto" },
},
```

```zig
// build.zig
const zcrypto_dep = b.dependency("zcrypto", .{});
exe.root_module.addImport("zcrypto", zcrypto_dep.module("zcrypto"));
```

## Usage

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = /* your allocator */;

    // Hashing
    const digest = zcrypto.hash.sha256("hello");

    // HMAC
    const mac = zcrypto.hmac.hmacSha256("key", "message");

    // Authenticated encryption (XChaCha20-Poly1305, combined blob)
    const key: [zcrypto.aead.key_length]u8 = ...;
    const blob = try zcrypto.aead.encrypt(allocator, io, key, "secret", "aad");
    const plaintext = try zcrypto.aead.decrypt(allocator, key, blob, "aad");

    // Password hashing (Argon2id, OWASP defaults)
    const phc = try zcrypto.password.hash(allocator, io, "hunter2");
    const ok = try zcrypto.password.verify(allocator, io, phc, "hunter2");

    // CSPRNG
    const token = try zcrypto.random.randomString(allocator, io, 24, null);
}
```

## API

### `random`
- `randomBytesAlloc(allocator, io, n) ![]u8`
- `randomInt(io, T, min, max) T` — unbiased, via `std.Random.intRangeAtMost`
- `randomString(allocator, io, len, alphabet: ?[]const u8) ![]u8` — default alphabet is alphanumeric
- `csprng(source: *const std.Random.IoSource) std.Random` — for callers
  who need a `std.Random` to pass around; **`source` must outlive every
  use of the returned value** (`std.Random.IoSource.interface()` returns
  a `std.Random` holding a pointer back into `source` — passing a
  temporary here is a dangling-pointer bug caught the hard way while
  building this module; see `random.zig`'s doc comment)

### `hash`
- `sha256(data) [32]u8`, `sha512(data) [64]u8`, `blake3(data) [32]u8`
- `Algorithm` enum (`.sha256`/`.sha512`/`.blake3`) + `digestLength(alg)`
  + `hash(alg, data, out: []u8)` for runtime dispatch

### `hmac`
- `hmacSha256(key, data) [32]u8`, `hmacSha512(key, data) [64]u8`

### `aead`
- `encrypt(allocator, io, key: [32]u8, plaintext, aad) ![]u8` — returns
  `nonce (24B) || ciphertext || tag (16B)` as one blob
- `decrypt(allocator, key: [32]u8, blob, aad) ![]u8` —
  `error.AuthenticationFailed` on any tampering/wrong key/wrong aad,
  `error.InvalidBlob` if too short to be real

### `password`
- `hash(allocator, io, password) ![]u8` — Argon2id, `Params.owasp_2id`, PHC string
- `verify(allocator, io, phc_str, password) !bool` — `false` for a wrong
  password, an error only for a malformed string or OOM

## Roadmap

Step 2 of a 4-phase plan: [`z-uuid`](https://github.com/carlos-sweb/z-uuid)
(UUID v4/v7) shipped first. Next is wiring both into
[`z-run`](https://github.com/carlos-sweb/z-run)'s `os` global as a nested
`os.crypto.*` namespace. Deliberately out of scope for now: more AEAD
ciphers (AES-GCM, plain ChaCha20-Poly1305), configurable Argon2 params,
and higher-level protocols (JWT, TOTP/HOTP, key wrapping).
