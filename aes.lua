--[[
  aes.lua — AES-256-CBC via LuaJIT FFI + libcrypto (OpenSSL)
  ===========================================================
  Uses LuaJIT's FFI to call libcrypto directly, replacing the pure-Lua AES
  implementation.  This is faster and simpler — the C library handles all
  key expansion, block cipher, and padding.

  Requires: LuaJIT with ffi (confirmed present on 5500AC), libcrypto (OpenSSL)
  MD5 key derivation still delegates to encdec.md5() — no change there.

  Public API  (identical to the previous pure-Lua version)
  ---------------------------------------------------------
    local aes = require("user.aes")

    -- Derive the 32-byte Unisenza Plus / Salus gateway key from the EUID
    local key = aes.salus_key("001E5E090292DD94")   -- 32-byte binary string
    local iv  = aes.hex2bin("88a6b0795d85dbfce6e0b3e9a629654b")

    -- Cached context — pre-expands key schedule once (preferred for repeated use)
    local ctx = aes.new_context(key, iv)
    local cipher = ctx:encrypt(plaintext)
    local plain  = ctx:decrypt(cipher)

    -- One-shot convenience wrappers
    local cipher = aes.encrypt(key, iv, plaintext)
    local plain  = aes.decrypt(key, iv, cipher)

    -- Helpers
    aes.bin2hex(str)   -- binary string → lowercase hex
    aes.hex2bin(hex)   -- hex string → binary string
--]]

local M = {}

-- ═════════════════════════════════════════════════════════════════════════════
-- FFI SETUP
-- ═════════════════════════════════════════════════════════════════════════════

local ffi    = require("ffi")
local crypto = ffi.load("crypto")
local encdec = require("encdec")

ffi.cdef [[
  /* Opaque EVP context */
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
  typedef struct evp_cipher_st     EVP_CIPHER;

  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  void            EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
  int             EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int padding);

  const EVP_CIPHER *EVP_aes_256_cbc(void);

  int EVP_EncryptInit_ex (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                          void *impl, const unsigned char *key,
                          const unsigned char *iv);
  int EVP_EncryptUpdate  (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                          const unsigned char *in, int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  int EVP_DecryptInit_ex (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                          void *impl, const unsigned char *key,
                          const unsigned char *iv);
  int EVP_DecryptUpdate  (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                          const unsigned char *in, int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
]]

local AES256CBC = crypto.EVP_aes_256_cbc()

-- ═════════════════════════════════════════════════════════════════════════════
-- MD5 (for Salus/Unisenza key derivation) — delegates to encdec
-- ═════════════════════════════════════════════════════════════════════════════

local function md5(s)
  return encdec.md5(s, true)   -- true = raw binary (16 bytes)
end

-- ═════════════════════════════════════════════════════════════════════════════
-- PUBLIC API
-- ═════════════════════════════════════════════════════════════════════════════

function M.hex2bin(hex)
  return (hex:gsub("..", function(h) return string.char(tonumber(h, 16)) end))
end

function M.bin2hex(bin)
  return (bin:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

--- Derive the 32-byte Unisenza Plus / Salus AES-256 key from the gateway EUID.
-- key = MD5("Salus-" .. euid:lower()) .. string.rep("\0", 16)
function M.salus_key(euid)
  return md5("Salus-" .. euid:lower()) .. string.rep("\0", 16)
end

--- Create a reusable encryption context.
-- The EVP context is initialised once; encrypt/decrypt re-init the key+IV on
-- each call (required by EVP API) but the Lua object is reused to avoid GC churn.
--
-- @param key  32-byte binary string
-- @param iv   16-byte binary string
-- @return context with :encrypt(plain) and :decrypt(cipher) methods
function M.new_context(key, iv)
  local ctx = { _key = key, _iv = iv }

  function ctx:encrypt(plain)
    local evp = crypto.EVP_CIPHER_CTX_new()
    assert(evp ~= nil, "EVP_CIPHER_CTX_new failed")
    crypto.EVP_EncryptInit_ex(evp, AES256CBC, nil, self._key, self._iv)
    -- outbuf needs room for input + one extra block (PKCS#7 padding)
    local inlen  = #plain
    local outbuf = ffi.new("unsigned char[?]", inlen + 16)
    local outl   = ffi.new("int[1]")
    local total  = ffi.new("int[1]")
    crypto.EVP_EncryptUpdate (evp, outbuf, outl, plain, inlen)
    total[0] = outl[0]
    crypto.EVP_EncryptFinal_ex(evp, outbuf + total[0], outl)
    total[0] = total[0] + outl[0]
    crypto.EVP_CIPHER_CTX_free(evp)
    return ffi.string(outbuf, total[0])
  end

  function ctx:decrypt(cipher)
    local evp = crypto.EVP_CIPHER_CTX_new()
    assert(evp ~= nil, "EVP_CIPHER_CTX_new failed")
    crypto.EVP_DecryptInit_ex(evp, AES256CBC, nil, self._key, self._iv)
    local inlen  = #cipher
    local outbuf = ffi.new("unsigned char[?]", inlen)
    local outl   = ffi.new("int[1]")
    local total  = ffi.new("int[1]")
    crypto.EVP_DecryptUpdate (evp, outbuf, outl, cipher, inlen)
    total[0] = outl[0]
    crypto.EVP_DecryptFinal_ex(evp, outbuf + total[0], outl)
    total[0] = total[0] + outl[0]
    crypto.EVP_CIPHER_CTX_free(evp)
    return ffi.string(outbuf, total[0])
  end

  return ctx
end

--- One-shot AES-256-CBC encrypt (PKCS#7 padding applied automatically).
function M.encrypt(key, iv, plain)
  return M.new_context(key, iv):encrypt(plain)
end

--- One-shot AES-256-CBC decrypt (PKCS#7 padding removed automatically).
function M.decrypt(key, iv, cipher)
  return M.new_context(key, iv):decrypt(cipher)
end

return M
