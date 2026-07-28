# z-crypto

Thin, ergonomic wrappers over `std.crypto` — CSPRNG, hashing, HMAC,
authenticated encryption, Argon2id password hashing, base32, TOTP/HOTP,
and compact JWS (HS256). Pure Zig, zero dependencies beyond `std`.

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

    // TOTP (RFC 6238) -- 2FA compatible with Google Authenticator/Authy
    const secret = try zcrypto.base32.decodeAlloc(allocator, "JBSWY3DPEHPK3PXP");
    var code_buf: [6]u8 = undefined;
    const code = zcrypto.totp.totpNow(secret, io, 30, 6, &code_buf);

    // Compact JWS (HS256) -- header/payload are caller-serialized JSON
    const token_jws = try zcrypto.jws.sign(allocator, "{\"alg\":\"HS256\"}", "{\"sub\":\"1\"}", "jwt-key");
    const verified = try zcrypto.jws.verify(allocator, token_jws, "jwt-key");
    defer verified.deinit(allocator);
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

### `base32`
- `encodeAlloc(allocator, data) ![]u8`, `decodeAlloc(allocator, encoded) ![]u8`
  — RFC 4648, uppercase alphabet; decode tolerates missing `=` padding
  and lowercase input (how TOTP secrets are usually shown)

### `totp`
- `hotp(secret, counter, digits, buf) []const u8` — RFC 4226, zero-padded
  into a caller buffer (a bare integer would silently drop leading zeros)
- `totp(secret, unix_time, step_seconds, digits, buf) []const u8` — RFC 6238
- `totpNow(secret, io, step_seconds, digits, buf) []const u8` — reads the
  real clock via `std.Io.Clock.real`
- `verifyTotp(secret, code, unix_time, step_seconds, digits, window) bool`
  — `window` steps of clock-drift tolerance either side

HMAC-SHA1, not the excluded raw-SHA1 hash — see `hmac.zig`'s doc comment
and `plan.md`'s exclusion list for why that's not a contradiction.

### `jws`
- `sign(allocator, header_json, payload_json, key) ![]u8` — compact JWS,
  HS256 only
- `verify(allocator, token, key) !Verified` (`.header_json`/
  `.payload_json`, caller-freed via `.deinit(allocator)`) —
  `error.InvalidSignature`/`error.MalformedToken`

Signing mechanics only, no claim validation (`exp`/`aud`/...) — that
needs a JSON parser, which `z-crypto` deliberately doesn't depend on.
Named `jws`, not `jwt`, to be honest about that boundary.

## Roadmap

4-phase plan, all shipped: [`z-uuid`](https://github.com/carlos-sweb/z-uuid)
(UUID v4/v7), this repo (phase 2 core primitives + phase 4 TOTP/JWS), and
[`z-run`](https://github.com/carlos-sweb/z-run)'s `os.crypto.*` wiring
(phase 3). Deliberately out of scope: more AEAD ciphers (AES-GCM, plain
ChaCha20-Poly1305), configurable Argon2 params, AES-KW key wrapping
(envelope encryption is already just `aead.encrypt` with a KEK), JWS
algorithms other than HS256, and full JWT claim validation.
