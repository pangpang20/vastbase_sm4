# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SM4 (GB/T 32907-2016) block cipher extension for VastBase/OpenGauss databases. Provides SQL-callable encryption/decryption functions in ECB, CBC, and GCM modes via a C shared library (`sm4.so`).

## Build Commands

Requires `$VBHOME` set to the VastBase install path (default: `/home/vastbase/vasthome`) and OpenSSL dev libraries (1.1.1+ or 3.0+).

```bash
# Set environment
export VBHOME=/home/vastbase/vasthome
export PATH=$VBHOME/bin:$PATH
export LD_LIBRARY_PATH=$VBHOME/lib:$LD_LIBRARY_PATH

# Build (compiles sm4.c + sm4_ext.c -> sm4.so via g++)
make clean && make

# Install: copies sm4.so to $VBHOME/lib/postgresql/, control+sql to extension/
make install
# Also copy to proc_srclib (required by VastBase):
mkdir -p $VBHOME/lib/postgresql/proc_srclib
cp $VBHOME/lib/postgresql/sm4.so $VBHOME/lib/postgresql/proc_srclib/
```

## Testing

VastBase does not support `CREATE EXTENSION`. Enable functions by running the SQL file directly on each target database:

```bash
vsql -d <database> -f sm4--1.0.sql   # creates all sm4_c_* functions
```

Run integration tests (requires a running VastBase instance with functions installed):

```bash
vsql -d test01 -f test_sm4.sql         # ECB/CBC mode tests
vsql -d test01 -f test_sm4_gcm.sql     # GCM mode tests
vsql -d test01 -f demo_citizen_data.sql # citizen data demo
```

There are no C-level unit tests (see `docs/requirements/feature-10.md`).

## Architecture

Three source files, compiled into a single `sm4.so` shared library:

- **`sm4.h` / `sm4.c`** — Pure SM4 algorithm implementation (no database dependency). Contains the S-box, key expansion, block encrypt/decrypt, PKCS7 padding, ECB/CBC/GCM modes, and PBKDF2-based key derivation. GCM mode includes a full GF(2^128) multiplication implementation.

- **`sm4_ext.c`** — PostgreSQL/VastBase C extension interface. Bridges SQL function calls to the SM4 algorithm. Contains `PG_MODULE_MAGIC`, `PG_FUNCTION_INFO_V1` declarations for 10 functions, and utility code (hex conversion, Base64 encode/decode, key parsing). Keys accept either 16-byte raw strings or 32-char hex strings.

- **`sm4--1.0.sql`** — SQL function definitions. All functions use the `sm4_c_` prefix to avoid conflicts with Java UDFs in VastBase.

### SQL Function Surface

| Function | Mode | Returns |
|----------|------|---------|
| `sm4_c_encrypt` / `sm4_c_decrypt` | ECB | bytea / text |
| `sm4_c_encrypt_hex` / `sm4_c_decrypt_hex` | ECB | text (hex) |
| `sm4_c_encrypt_cbc` / `sm4_c_decrypt_cbc` | CBC | bytea / text |
| `sm4_c_encrypt_gcm` / `sm4_c_decrypt_gcm` | GCM | bytea (cipher+tag) / text |
| `sm4_c_encrypt_gcm_base64` / `sm4_c_decrypt_gcm_base64` | GCM | text (Base64) |
| `sm4_c_encrypt_gcm_auto_iv` / `sm4_c_decrypt_gcm_auto_iv` | GCM (auto IV) | bytea (IV+cipher+tag) / text |
| `sm4_c_encrypt_gcm_auto_iv_base64` / `sm4_c_decrypt_gcm_auto_iv_base64` | GCM (auto IV) | text (Base64) |

## Key Conventions

- Compiled with `g++ -std=c++11` (not gcc) due to `extern "C"` linkage in `sm4_ext.c`
- Compiler flag `-DUSE_OPENSSL_KDF` enables PBKDF2 key derivation via OpenSSL
- SQL functions are `STRICT` (NULL input returns NULL) except GCM variants which have `DEFAULT NULL` AAD parameters
- Functions are declared `IMMUTABLE` in PostgreSQL terms
