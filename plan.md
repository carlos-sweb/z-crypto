# z-crypto — listado de características investigadas

Investigación hecha contra `std.crypto` de Zig 0.16 (instalado en
`~/.local/share/mise/installs/zig/0.16.0/lib/std/crypto`). Se marca **[std]**
lo que la stdlib ya resuelve (envolver, no reinventar) y **[nuevo]** lo que
hay que construir. Se excluyen deliberadamente los algoritmos ya probados
como inseguros (ver sección final) — no se ofrecen ni siquiera como opción
"legacy", siguiendo la filosofía de librerías como libsodium.

## 1. Identificadores únicos
- UUID v4 (random) **[nuevo]**
- UUID v7 (time-ordered) **[nuevo]** — el más pedido hoy, bueno para índices de DB
- ULID **[nuevo]** — alternativa a v7, encoding Crockford base32
- CUID2, NanoID, KSUID **[nuevo]** — opcionales, para URLs cortas

## 2. Aleatoriedad segura (CSPRNG)
- `std.crypto.random` ya expone el CSPRNG del SO **[std]**
- Fachada propia: `randomBytes(n)`, `randomInt(T, min, max)` sin sesgo de
  módulo, `randomString`/token alfanumérico para API keys y OTP **[nuevo,
  wrapper fino]**

## 3. Cifrado simétrico autenticado (AEAD)
- AES-128/256-GCM **[std]**
- ChaCha20-Poly1305, XChaCha20-Poly1305 **[std]**
- AES-GCM-SIV, AES-OCB, AES-CCM, AES-SIV **[std]**
- Ascon-128, AEGIS **[std]** — variantes ligeras (IoT/embedded)
- API unificada de conveniencia `encrypt(alg, key, plaintext, aad)` **[nuevo]**

## 4. Derivación de claves para contraseñas
- Argon2i/Argon2id **[std]**
- scrypt **[std]**
- bcrypt **[std]**
- PBKDF2 **[std]**
- HKDF **[std]**
- API `hashPassword`/`verifyPassword` con parámetros por defecto sensatos,
  sobre el encoding PHC que ya trae std **[nuevo, capa de conveniencia]**

## 5. Asimétrica y firmas
- Ed25519, X25519, Ristretto255 **[std]**
- ECDSA sobre P-256/P-384/secp256k1 **[std]**
- ML-KEM (Kyber) y ML-DSA (Dilithium) — post-cuántica, ya en std 0.16 **[std]**
- RSA — std NO lo trae; solo si hace falta interoperar con sistemas legados
  que lo exigen **[nuevo, evaluar si vale la pena]**
- Serialización de claves (PEM/DER/PKCS#8/JWK) **[nuevo]**

## 6. Hash y MAC (solo algoritmos vigentes)
- SHA-256/384/512, SHA-3 **[std]**
- BLAKE2b/s, BLAKE3, KangarooTwelve **[std]**
- HMAC, CMAC, SipHash **[std]**
- API genérica `hash(alg, data)` / `hmac(alg, key, data)` con enum de
  algoritmos **[nuevo, capa de conveniencia]**

## 7. Codificación / formatos
- Hex, Base64 **[std]**
- Base58 (Bitcoin-style), Base62 **[nuevo]**
- PEM (generación; el parsing de certificados ya está en std) **[nuevo]**

## 8. Utilidades de seguridad
- Comparación en tiempo constante **[std]**
- Borrado seguro de memoria (`secureZero`) **[std]**
- Tipo `SecretBytes`/`Zeroizing` que auto-limpia al `deinit` **[nuevo]**

## 9. Protocolos de alto nivel
- JWT/JWS (firmar/verificar tokens) **[nuevo]**
- TOTP/HOTP (RFC 6238/4226) — 2FA compatible con Google Authenticator **[nuevo]**
- Envelope encryption / key wrapping (AES-KW) **[nuevo]**
- Shamir Secret Sharing **[nuevo, opcional]**
- Formato tipo `age` (cifrado de archivos con clave pública) **[nuevo, opcional]**

## 10. TLS/Certificados
- Parsing de certificados X.509 **[std]**
- Cliente TLS **[std]**
- Generación de certificados/CSRs **[nuevo, probablemente fuera de alcance]**

## 11. Calidad/ergonomía de la librería
- Vectores de prueba oficiales (NIST KAT, RFC test vectors) por cada primitivo
- API allocator-aware sin forzar heap donde no haga falta
- Sin dependencias externas más allá de `std`
- Comportamiento constant-time idéntico en `Debug` y `ReleaseFast`

## Excluido a propósito: algoritmos ya probados inseguros

No se implementan ni se exponen, ni siquiera como opción "legacy" u
"compatibilidad" — quien los necesite debe usar otra librería a propósito,
no encontrarlos disponibles por accidente en `z-crypto`:

- **MD5** — colisiones prácticas demostradas desde 2004.
- **SHA-1** — colisiones prácticas demostradas (ataque SHAttered, 2017).
- **DES / 3DES** — clave de 56 bits (DES) rota por fuerza bruta; 3DES
  deprecado por NIST.
- **RC4** — sesgos estadísticos explotables en el keystream.
- **Modo ECB** (en cualquier cifrador de bloque) — filtra patrones del
  plaintext, no debe existir como modo seleccionable.
