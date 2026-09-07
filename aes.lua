--[[
  aes.lua — Pure-Lua AES-256-CBC + MD5  (Lua 5.1 compatible)
  ============================================================
  For use on C-Bus SpaceLogic 5500AC / LogicMachine controllers.
  No external dependencies — uses only the Lua 5.1 standard library.

  Public API
  ----------
    local aes = require("aes")

    local key = aes.salus_key("001E5E090292DD94")   -- 32-byte binary string
    local iv  = aes.hex2bin("88a6b0795d85dbfce6e0b3e9a629654b")

    local cipher = aes.encrypt(key, iv, plaintext)  -- binary → binary
    local plain  = aes.decrypt(key, iv, cipher)      -- binary → binary

    aes.bin2hex(str)   -- binary → lowercase hex
    aes.hex2bin(hex)   -- hex string → binary
--]]

local M = {}

-- ═════════════════════════════════════════════════════════════════════════════
-- BITWISE HELPERS (Lua 5.1 — no built-in bit ops)
-- ═════════════════════════════════════════════════════════════════════════════

-- XOR two bytes (0-255)
local _xor_cache = {}
local function bxor(a, b)
  local key = a * 256 + b
  local c = _xor_cache[key]
  if c then return c end
  local r, p = 0, 1
  local aa, bb = a, b
  for _ = 1, 8 do
    if aa % 2 ~= bb % 2 then r = r + p end
    aa, bb, p = math.floor(aa / 2), math.floor(bb / 2), p * 2
  end
  _xor_cache[key] = r
  return r
end

-- xtime: multiply byte by 2 in GF(2^8)
local xtime = {}
for i = 0, 255 do
  local v = i * 2
  if v >= 256 then v = v - 256 end          -- mod 256
  if i >= 128 then v = bxor(v, 0x1b) end   -- reduce by x^8 + x^4 + x^3 + x + 1
  xtime[i] = v
end

-- Multiply two bytes in GF(2^8)
local function gmul(a, b)
  local p = 0
  local aa = a
  for _ = 1, 8 do
    if b % 2 == 1 then p = bxor(p, aa) end
    b = math.floor(b / 2)
    aa = xtime[aa]
  end
  return p
end

-- XOR two equal-length binary strings
local function xor_str(a, b)
  local t = {}
  for i = 1, #a do
    t[i] = string.char(bxor(string.byte(a, i), string.byte(b, i)))
  end
  return table.concat(t)
end

-- ═════════════════════════════════════════════════════════════════════════════
-- MD5 (for Salus key derivation)
-- ═════════════════════════════════════════════════════════════════════════════

-- Addition mod 2^32
local function add32(...)
  local s = 0
  for _, v in ipairs({...}) do s = (s + v) % 2^32 end
  return s
end

-- Left-rotate 32-bit value
local function rotl32(x, n)
  x = x % 2^32
  local hi = math.floor(x / 2^(32-n)) % 2^n
  local lo = (x * 2^n) % 2^32
  return lo + hi
end

-- Byte-level XOR for 32-bit values (avoids the cache cost of bxor on large numbers)
local function xor32(a, b)
  local r, p = 0, 1
  for _ = 1, 32 do
    if a % 2 ~= b % 2 then r = r + p end
    a, b, p = math.floor(a/2), math.floor(b/2), p * 2
  end
  return r
end

local function and32(a, b)
  local r, p = 0, 1
  for _ = 1, 32 do
    if a % 2 == 1 and b % 2 == 1 then r = r + p end
    a, b, p = math.floor(a/2), math.floor(b/2), p * 2
  end
  return r
end

local function or32(a, b)
  local r, p = 0, 1
  for _ = 1, 32 do
    if a % 2 == 1 or b % 2 == 1 then r = r + p end
    a, b, p = math.floor(a/2), math.floor(b/2), p * 2
  end
  return r
end

local function not32(x)
  return (2^32 - 1) - (x % 2^32)
end

-- Precomputed T[i] = floor(2^32 * abs(sin(i))), i=1..64
local T = {}
for i = 1, 64 do
  T[i] = math.floor(math.abs(math.sin(i)) * 2^32) % 2^32
end

local function md5(s)
  -- Padding
  local len = #s
  s = s .. "\128"
  while #s % 64 ~= 56 do s = s .. "\0" end
  local bits = len * 8
  for i = 0, 3 do s = s .. string.char(math.floor(bits / 2^(8*i)) % 256) end
  for _ = 1, 4    do s = s .. "\0" end   -- high 32 bits of length (always 0 here)

  local a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

  for blk = 0, (#s / 64) - 1 do
    local X = {}
    for j = 0, 15 do
      local base = blk * 64 + j * 4 + 1
      X[j] =  string.byte(s, base)
           + (string.byte(s, base+1) * 256)
           + (string.byte(s, base+2) * 65536)
           + (string.byte(s, base+3) * 16777216)
    end

    local A, B, C, D = a0, b0, c0, d0

    local function F(x,y,z) return or32(and32(x,y), and32(not32(x),z)) end
    local function G(x,y,z) return or32(and32(x,z), and32(y,not32(z))) end
    local function H(x,y,z) return xor32(xor32(x,y),z) end
    local function I(x,y,z) return xor32(y, or32(x, not32(z))) end

    local function step(fn, k, s2, ti)
      local t = add32(A, fn(B,C,D), X[k], T[ti])
      A, B, C, D = D, add32(B, rotl32(t, s2)), B, C
    end

    -- Round 1
    step(F, 0, 7, 1);step(F, 1,12, 2);step(F, 2,17, 3);step(F, 3,22, 4)
    step(F, 4, 7, 5);step(F, 5,12, 6);step(F, 6,17, 7);step(F, 7,22, 8)
    step(F, 8, 7, 9);step(F, 9,12,10);step(F,10,17,11);step(F,11,22,12)
    step(F,12, 7,13);step(F,13,12,14);step(F,14,17,15);step(F,15,22,16)
    -- Round 2
    step(G, 1, 5,17);step(G, 6, 9,18);step(G,11,14,19);step(G, 0,20,20)
    step(G, 5, 5,21);step(G,10, 9,22);step(G,15,14,23);step(G, 4,20,24)
    step(G, 9, 5,25);step(G,14, 9,26);step(G, 3,14,27);step(G, 8,20,28)
    step(G,13, 5,29);step(G, 2, 9,30);step(G, 7,14,31);step(G,12,20,32)
    -- Round 3
    step(H, 5, 4,33);step(H, 8,11,34);step(H,11,16,35);step(H,14,23,36)
    step(H, 1, 4,37);step(H, 4,11,38);step(H, 7,16,39);step(H,10,23,40)
    step(H,13, 4,41);step(H, 0,11,42);step(H, 3,16,43);step(H, 6,23,44)
    step(H, 9, 4,45);step(H,12,11,46);step(H,15,16,47);step(H, 2,23,48)
    -- Round 4
    step(I, 0, 6,49);step(I, 7,10,50);step(I,14,15,51);step(I, 5,21,52)
    step(I,12, 6,53);step(I, 3,10,54);step(I,10,15,55);step(I, 1,21,56)
    step(I, 8, 6,57);step(I,15,10,58);step(I, 6,15,59);step(I,13,21,60)
    step(I, 4, 6,61);step(I,11,10,62);step(I, 2,15,63);step(I, 9,21,64)

    a0 = add32(a0,A); b0 = add32(b0,B); c0 = add32(c0,C); d0 = add32(d0,D)
  end

  local function le32(v)
    return string.char( v       % 256,
                        math.floor(v/256)     % 256,
                        math.floor(v/65536)   % 256,
                        math.floor(v/16777216)% 256 )
  end
  return le32(a0) .. le32(b0) .. le32(c0) .. le32(d0)
end

-- ═════════════════════════════════════════════════════════════════════════════
-- AES-256 (FIPS 197)
-- ═════════════════════════════════════════════════════════════════════════════

local S_BOX = {
   99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118,
  202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
  183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
    4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117,
    9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
   83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
  208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168,
   81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
  205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
   96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
  224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121,
  231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8,
  186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
  112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158,
  225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
  140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22,
}

-- Build 0-indexed S and inverse-S
local S = {}; local Si = {}
for i, v in ipairs(S_BOX) do S[i-1] = v end
for i = 0, 255 do Si[S[i]] = i end

-- AES round constants
local RCON = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 }

-- Key expansion — AES-256 (Nk=8, Nr=14)
-- Returns W: array[0..59] of 4-byte arrays {b0,b1,b2,b3}
local function keyExpand(key)
  local Nk, Nr = 8, 14
  local W = {}
  for i = 0, Nk-1 do
    local b = i*4+1
    W[i] = { string.byte(key,b), string.byte(key,b+1),
              string.byte(key,b+2), string.byte(key,b+3) }
  end
  for i = Nk, 4*(Nr+1)-1 do
    local t = { W[i-1][1], W[i-1][2], W[i-1][3], W[i-1][4] }
    if i % Nk == 0 then
      -- RotWord: rotate left by 1 byte, then SubWord, then XOR Rcon
      t = { bxor(S[t[2]], RCON[i/Nk]),
            S[t[3]], S[t[4]], S[t[1]] }
    elseif i % Nk == 4 then
      t = { S[t[1]], S[t[2]], S[t[3]], S[t[4]] }
    end
    W[i] = { bxor(W[i-Nk][1],t[1]), bxor(W[i-Nk][2],t[2]),
              bxor(W[i-Nk][3],t[3]), bxor(W[i-Nk][4],t[4]) }
  end
  return W, Nr
end

-- Input/output block representation:
--   The 16-byte block is stored as state[col][row], col=0..3, row=0..3
--   state[c][r] = byte at position col*4+row (column-major, per FIPS 197)

local function block_to_state(blk)
  local st = {}
  for c = 0, 3 do
    st[c] = {}
    for r = 0, 3 do
      st[c][r] = string.byte(blk, c*4+r+1)
    end
  end
  return st
end

local function state_to_block(st)
  local t = {}
  for c = 0, 3 do
    for r = 0, 3 do
      t[#t+1] = string.char(st[c][r])
    end
  end
  return table.concat(t)
end

local function addRoundKey(st, W, rnd)
  for c = 0, 3 do
    local kw = W[rnd*4 + c]
    st[c][0] = bxor(st[c][0], kw[1])
    st[c][1] = bxor(st[c][1], kw[2])
    st[c][2] = bxor(st[c][2], kw[3])
    st[c][3] = bxor(st[c][3], kw[4])
  end
end

local function subBytes(st)
  for c = 0, 3 do
    for r = 0, 3 do st[c][r] = S[st[c][r]] end
  end
end

local function invSubBytes(st)
  for c = 0, 3 do
    for r = 0, 3 do st[c][r] = Si[st[c][r]] end
  end
end

-- ShiftRows operates on rows (row r shifts left by r positions)
local function shiftRows(st)
  -- row 1: left 1
  st[0][1],st[1][1],st[2][1],st[3][1] = st[1][1],st[2][1],st[3][1],st[0][1]
  -- row 2: left 2
  st[0][2],st[1][2],st[2][2],st[3][2] = st[2][2],st[3][2],st[0][2],st[1][2]
  -- row 3: left 3 (= right 1)
  st[0][3],st[1][3],st[2][3],st[3][3] = st[3][3],st[0][3],st[1][3],st[2][3]
end

local function invShiftRows(st)
  -- row 1: right 1
  st[0][1],st[1][1],st[2][1],st[3][1] = st[3][1],st[0][1],st[1][1],st[2][1]
  -- row 2: right 2
  st[0][2],st[1][2],st[2][2],st[3][2] = st[2][2],st[3][2],st[0][2],st[1][2]
  -- row 3: right 3 (= left 1)
  st[0][3],st[1][3],st[2][3],st[3][3] = st[1][3],st[2][3],st[3][3],st[0][3]
end

local function mixColumns(st)
  for c = 0, 3 do
    local s0,s1,s2,s3 = st[c][0],st[c][1],st[c][2],st[c][3]
    st[c][0] = bxor(bxor(bxor(gmul(s0,2), gmul(s1,3)), s2), s3)
    st[c][1] = bxor(bxor(bxor(s0, gmul(s1,2)), gmul(s2,3)), s3)
    st[c][2] = bxor(bxor(bxor(s0, s1), gmul(s2,2)), gmul(s3,3))
    st[c][3] = bxor(bxor(bxor(gmul(s0,3), s1), s2), gmul(s3,2))
  end
end

local function invMixColumns(st)
  for c = 0, 3 do
    local s0,s1,s2,s3 = st[c][0],st[c][1],st[c][2],st[c][3]
    st[c][0] = bxor(bxor(bxor(gmul(s0,14),gmul(s1,11)),gmul(s2,13)),gmul(s3, 9))
    st[c][1] = bxor(bxor(bxor(gmul(s0, 9),gmul(s1,14)),gmul(s2,11)),gmul(s3,13))
    st[c][2] = bxor(bxor(bxor(gmul(s0,13),gmul(s1, 9)),gmul(s2,14)),gmul(s3,11))
    st[c][3] = bxor(bxor(bxor(gmul(s0,11),gmul(s1,13)),gmul(s2, 9)),gmul(s3,14))
  end
end

local function aes_encrypt_block(blk, W, Nr)
  local st = block_to_state(blk)
  addRoundKey(st, W, 0)
  for r = 1, Nr-1 do
    subBytes(st); shiftRows(st); mixColumns(st); addRoundKey(st, W, r)
  end
  subBytes(st); shiftRows(st); addRoundKey(st, W, Nr)
  return state_to_block(st)
end

local function aes_decrypt_block(blk, W, Nr)
  local st = block_to_state(blk)
  addRoundKey(st, W, Nr)
  for r = Nr-1, 1, -1 do
    invShiftRows(st); invSubBytes(st); addRoundKey(st, W, r); invMixColumns(st)
  end
  invShiftRows(st); invSubBytes(st); addRoundKey(st, W, 0)
  return state_to_block(st)
end

-- PKCS#7
local function pad(data)
  local p = 16 - (#data % 16)
  return data .. string.rep(string.char(p), p)
end
local function unpad(data)
  local p = string.byte(data, #data)
  return string.sub(data, 1, #data - p)
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

--- Create a reusable encryption context — pre-expands the key schedule once.
-- Use this instead of calling encrypt/decrypt directly when the same key is
-- used repeatedly (e.g. every 30-second poll).  The key expansion is the most
-- CPU-intensive part of AES; caching it avoids re-running it on every request.
--
-- @param key  32-byte binary string (from M.salus_key)
-- @param iv   16-byte binary string (from M.hex2bin)
-- @return context object with :encrypt(plain) and :decrypt(cipher) methods
function M.new_context(key, iv)
  local W, Nr = keyExpand(key)
  local ctx = { _W = W, _Nr = Nr, _iv = iv }

  function ctx:encrypt(plain)
    local padded = pad(plain)
    local out, prev = {}, self._iv
    for i = 1, #padded, 16 do
      local blk = string.sub(padded, i, i+15)
      prev = aes_encrypt_block(xor_str(blk, prev), self._W, self._Nr)
      out[#out+1] = prev
    end
    return table.concat(out)
  end

  function ctx:decrypt(cipher)
    local out, prev = {}, self._iv
    for i = 1, #cipher, 16 do
      local blk = string.sub(cipher, i, i+15)
      out[#out+1] = xor_str(aes_decrypt_block(blk, self._W, self._Nr), prev)
      prev = blk
    end
    return unpad(table.concat(out))
  end

  return ctx
end

--- AES-256-CBC encrypt (PKCS#7 padding applied automatically).
-- Prefer M.new_context() when the same key is used more than once.
function M.encrypt(key, iv, plain)
  local W, Nr = keyExpand(key)
  local padded = pad(plain)
  local out, prev = {}, iv
  for i = 1, #padded, 16 do
    local blk = string.sub(padded, i, i+15)
    prev = aes_encrypt_block(xor_str(blk, prev), W, Nr)
    out[#out+1] = prev
  end
  return table.concat(out)
end

--- AES-256-CBC decrypt (PKCS#7 padding removed automatically).
-- Prefer M.new_context() when the same key is used more than once.
function M.decrypt(key, iv, cipher)
  local W, Nr = keyExpand(key)
  local out, prev = {}, iv
  for i = 1, #cipher, 16 do
    local blk = string.sub(cipher, i, i+15)
    out[#out+1] = xor_str(aes_decrypt_block(blk, W, Nr), prev)
    prev = blk
  end
  return unpad(table.concat(out))
end

return M
