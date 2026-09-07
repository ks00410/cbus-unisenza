--[[
  aes.lua — AES-256-CBC for C-Bus SpaceLogic 5500AC / LogicMachine
  =================================================================
  Uses the built-in LogicMachine `bit` library for all bitwise operations,
  which avoids the expensive loop-based XOR/AND we would otherwise need in
  plain Lua 5.1.  On LogicMachine, `bit.bxor` etc. are always available
  without any require().

  If the `encdec` library is available (it is on LogicMachine), MD5 for key
  derivation is delegated to `encdec.md5()` instead of the pure-Lua fallback.

  Public API
  ----------
    local aes = require("aes")

    -- Derive the 32-byte Unisenza Plus / Salus gateway key from the EUID
    local key = aes.salus_key("001E5E090292DD94")   -- 32-byte binary string
    local iv  = aes.hex2bin("88a6b0795d85dbfce6e0b3e9a629654b")

    -- One-shot encrypt / decrypt
    local cipher = aes.encrypt(key, iv, plaintext)
    local plain  = aes.decrypt(key, iv, cipher)

    -- Cached context — pre-expands key schedule once (preferred for repeated use)
    local ctx = aes.new_context(key, iv)
    local cipher = ctx:encrypt(plaintext)
    local plain  = ctx:decrypt(cipher)

    -- Helpers
    aes.bin2hex(str)   -- binary string → lowercase hex
    aes.hex2bin(hex)   -- hex string → binary string
--]]

local M = {}

-- ═════════════════════════════════════════════════════════════════════════════
-- BITWISE HELPERS
-- Uses LogicMachine's built-in `bit` library (always available, no require).
-- Falls back to arithmetic loops when running outside LogicMachine (e.g. tests).
-- ═════════════════════════════════════════════════════════════════════════════

local _bxor, _band, _bor, _bnot, _lshift, _rshift

if bit then
  -- LogicMachine / LuaJIT bit library — single native call, fast
  _bxor   = bit.bxor
  _band   = bit.band
  _bor    = bit.bor
  _bnot   = function(x) return bit.bnot(x) % 0x100000000 end
  _lshift = bit.lshift
  _rshift = bit.rshift
else
  -- Pure-Lua fallback for testing outside LogicMachine (standard Lua 5.x)
  local function _loop_xor(a, b, bits)
    local r, p = 0, 1
    for _ = 1, bits do
      if a % 2 ~= b % 2 then r = r + p end
      a, b, p = math.floor(a/2), math.floor(b/2), p * 2
    end
    return r
  end
  _bxor   = function(a, b) return _loop_xor(a, b, 32) end
  _band   = function(a, b)
    local r, p = 0, 1
    for _ = 1, 32 do
      if a % 2 == 1 and b % 2 == 1 then r = r + p end
      a, b, p = math.floor(a/2), math.floor(b/2), p * 2
    end
    return r
  end
  _bor    = function(a, b)
    local r, p = 0, 1
    for _ = 1, 32 do
      if a % 2 == 1 or b % 2 == 1 then r = r + p end
      a, b, p = math.floor(a/2), math.floor(b/2), p * 2
    end
    return r
  end
  _bnot   = function(x) return (2^32 - 1) - x % 2^32 end
  _lshift = function(x, n) return (x * 2^n) % 2^32 end
  _rshift = function(x, n) return math.floor(x / 2^n) % 2^32 end
end

-- Byte XOR (0-255) — used heavily in AES block operations
local function bxor8(a, b) return _bxor(a, b) % 256 end

-- xtime: multiply a byte by 2 in GF(2^8)
local xtime = {}
for i = 0, 255 do
  local v = i * 2
  if v >= 256 then v = v - 256 end
  if i >= 128 then v = bxor8(v, 0x1b) end
  xtime[i] = v
end

-- Multiply two bytes in GF(2^8) using xtime
local function gmul(a, b)
  local p = 0
  for _ = 1, 8 do
    if b % 2 == 1 then p = bxor8(p, a) end
    b = math.floor(b / 2)
    a = xtime[a]
  end
  return p
end

-- XOR two equal-length binary strings
local function xor_str(a, b)
  local t = {}
  for i = 1, #a do
    t[i] = string.char(bxor8(string.byte(a, i), string.byte(b, i)))
  end
  return table.concat(t)
end

-- ═════════════════════════════════════════════════════════════════════════════
-- MD5 (for Salus/Unisenza key derivation)
-- Delegates to encdec.md5() when available; otherwise uses a pure-Lua fallback.
-- ═════════════════════════════════════════════════════════════════════════════

local function md5(s)
  -- Try LogicMachine's built-in encdec library first (fast native C)
  local ok, enc = pcall(require, "encdec")
  if ok and enc.md5 then
    return enc.md5(s, true)   -- true = return raw binary (16 bytes)
  end

  -- Pure-Lua fallback (used when running outside LogicMachine, e.g. unit tests)
  local function add32(...) local s2=0; for _,v in ipairs({...}) do s2=(s2+v)%2^32 end; return s2 end
  local function rotl32(x, n)
    x = x % 2^32
    return _bor(_lshift(x, n), _rshift(x, 32-n)) % 2^32
  end
  local T = {}
  for i = 1, 64 do T[i] = math.floor(math.abs(math.sin(i)) * 2^32) % 2^32 end

  local len = #s
  s = s .. "\128"
  while #s % 64 ~= 56 do s = s .. "\0" end
  local bits = len * 8
  for i = 0, 3 do s = s .. string.char(math.floor(bits / 2^(8*i)) % 256) end
  for _  = 1, 4 do s = s .. "\0" end

  local a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

  for blk = 0, (#s / 64) - 1 do
    local X = {}
    for j = 0, 15 do
      local base = blk*64 + j*4 + 1
      X[j] = string.byte(s,base)
           + string.byte(s,base+1)*256
           + string.byte(s,base+2)*65536
           + string.byte(s,base+3)*16777216
    end
    local A, B, C, D = a0, b0, c0, d0
    local function F(x,y,z) return _bor(_band(x,y), _band(_bnot(x),z)) % 2^32 end
    local function G(x,y,z) return _bor(_band(x,z), _band(y,_bnot(z))) % 2^32 end
    local function H(x,y,z) return _bxor(_bxor(x,y),z) % 2^32 end
    local function I(x,y,z) return _bxor(y, _bor(x,_bnot(z))) % 2^32 end
    local function step(fn,k,s2,ti)
      local t = add32(A, fn(B,C,D), X[k], T[ti])
      A,B,C,D = D, add32(B, rotl32(t,s2)), B, C
    end
    step(F, 0, 7, 1);step(F, 1,12, 2);step(F, 2,17, 3);step(F, 3,22, 4)
    step(F, 4, 7, 5);step(F, 5,12, 6);step(F, 6,17, 7);step(F, 7,22, 8)
    step(F, 8, 7, 9);step(F, 9,12,10);step(F,10,17,11);step(F,11,22,12)
    step(F,12, 7,13);step(F,13,12,14);step(F,14,17,15);step(F,15,22,16)
    step(G, 1, 5,17);step(G, 6, 9,18);step(G,11,14,19);step(G, 0,20,20)
    step(G, 5, 5,21);step(G,10, 9,22);step(G,15,14,23);step(G, 4,20,24)
    step(G, 9, 5,25);step(G,14, 9,26);step(G, 3,14,27);step(G, 8,20,28)
    step(G,13, 5,29);step(G, 2, 9,30);step(G, 7,14,31);step(G,12,20,32)
    step(H, 5, 4,33);step(H, 8,11,34);step(H,11,16,35);step(H,14,23,36)
    step(H, 1, 4,37);step(H, 4,11,38);step(H, 7,16,39);step(H,10,23,40)
    step(H,13, 4,41);step(H, 0,11,42);step(H, 3,16,43);step(H, 6,23,44)
    step(H, 9, 4,45);step(H,12,11,46);step(H,15,16,47);step(H, 2,23,48)
    step(I, 0, 6,49);step(I, 7,10,50);step(I,14,15,51);step(I, 5,21,52)
    step(I,12, 6,53);step(I, 3,10,54);step(I,10,15,55);step(I, 1,21,56)
    step(I, 8, 6,57);step(I,15,10,58);step(I, 6,15,59);step(I,13,21,60)
    step(I, 4, 6,61);step(I,11,10,62);step(I, 2,15,63);step(I, 9,21,64)
    a0=add32(a0,A); b0=add32(b0,B); c0=add32(c0,C); d0=add32(d0,D)
  end

  local function le32(v)
    return string.char(v%256, math.floor(v/256)%256,
                       math.floor(v/65536)%256, math.floor(v/16777216)%256)
  end
  return le32(a0)..le32(b0)..le32(c0)..le32(d0)
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
local S = {}; local Si = {}
for i, v in ipairs(S_BOX) do S[i-1] = v end
for i = 0, 255 do Si[S[i]] = i end

local RCON = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 }

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
      t = { bxor8(S[t[2]], RCON[i/Nk]), S[t[3]], S[t[4]], S[t[1]] }
    elseif i % Nk == 4 then
      t = { S[t[1]], S[t[2]], S[t[3]], S[t[4]] }
    end
    W[i] = { bxor8(W[i-Nk][1],t[1]), bxor8(W[i-Nk][2],t[2]),
              bxor8(W[i-Nk][3],t[3]), bxor8(W[i-Nk][4],t[4]) }
  end
  return W, Nr
end

local function block_to_state(blk)
  local st = {}
  for c = 0, 3 do
    st[c] = {}
    for r = 0, 3 do st[c][r] = string.byte(blk, c*4+r+1) end
  end
  return st
end

local function state_to_block(st)
  local t = {}
  for c = 0, 3 do
    for r = 0, 3 do t[#t+1] = string.char(st[c][r]) end
  end
  return table.concat(t)
end

local function addRoundKey(st, W, rnd)
  for c = 0, 3 do
    local kw = W[rnd*4+c]
    st[c][0]=bxor8(st[c][0],kw[1]); st[c][1]=bxor8(st[c][1],kw[2])
    st[c][2]=bxor8(st[c][2],kw[3]); st[c][3]=bxor8(st[c][3],kw[4])
  end
end

local function subBytes(st)
  for c=0,3 do for r=0,3 do st[c][r]=S[st[c][r]] end end
end
local function invSubBytes(st)
  for c=0,3 do for r=0,3 do st[c][r]=Si[st[c][r]] end end
end

local function shiftRows(st)
  st[0][1],st[1][1],st[2][1],st[3][1] = st[1][1],st[2][1],st[3][1],st[0][1]
  st[0][2],st[1][2],st[2][2],st[3][2] = st[2][2],st[3][2],st[0][2],st[1][2]
  st[0][3],st[1][3],st[2][3],st[3][3] = st[3][3],st[0][3],st[1][3],st[2][3]
end
local function invShiftRows(st)
  st[0][1],st[1][1],st[2][1],st[3][1] = st[3][1],st[0][1],st[1][1],st[2][1]
  st[0][2],st[1][2],st[2][2],st[3][2] = st[2][2],st[3][2],st[0][2],st[1][2]
  st[0][3],st[1][3],st[2][3],st[3][3] = st[1][3],st[2][3],st[3][3],st[0][3]
end

local function mixColumns(st)
  for c=0,3 do
    local s0,s1,s2,s3=st[c][0],st[c][1],st[c][2],st[c][3]
    st[c][0]=bxor8(bxor8(bxor8(gmul(s0,2),gmul(s1,3)),s2),s3)
    st[c][1]=bxor8(bxor8(bxor8(s0,gmul(s1,2)),gmul(s2,3)),s3)
    st[c][2]=bxor8(bxor8(bxor8(s0,s1),gmul(s2,2)),gmul(s3,3))
    st[c][3]=bxor8(bxor8(bxor8(gmul(s0,3),s1),s2),gmul(s3,2))
  end
end
local function invMixColumns(st)
  for c=0,3 do
    local s0,s1,s2,s3=st[c][0],st[c][1],st[c][2],st[c][3]
    st[c][0]=bxor8(bxor8(bxor8(gmul(s0,14),gmul(s1,11)),gmul(s2,13)),gmul(s3, 9))
    st[c][1]=bxor8(bxor8(bxor8(gmul(s0, 9),gmul(s1,14)),gmul(s2,11)),gmul(s3,13))
    st[c][2]=bxor8(bxor8(bxor8(gmul(s0,13),gmul(s1, 9)),gmul(s2,14)),gmul(s3,11))
    st[c][3]=bxor8(bxor8(bxor8(gmul(s0,11),gmul(s1,13)),gmul(s2, 9)),gmul(s3,14))
  end
end

local function aes_encrypt_block(blk, W, Nr)
  local st = block_to_state(blk)
  addRoundKey(st,W,0)
  for r=1,Nr-1 do subBytes(st); shiftRows(st); mixColumns(st); addRoundKey(st,W,r) end
  subBytes(st); shiftRows(st); addRoundKey(st,W,Nr)
  return state_to_block(st)
end

local function aes_decrypt_block(blk, W, Nr)
  local st = block_to_state(blk)
  addRoundKey(st,W,Nr)
  for r=Nr-1,1,-1 do invShiftRows(st); invSubBytes(st); addRoundKey(st,W,r); invMixColumns(st) end
  invShiftRows(st); invSubBytes(st); addRoundKey(st,W,0)
  return state_to_block(st)
end

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
  return (hex:gsub("..", function(h) return string.char(tonumber(h,16)) end))
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
-- This is the preferred API when the same key is used repeatedly.
-- The key expansion is the most CPU-intensive part of AES; caching it means
-- it runs only once per controller restart regardless of poll frequency.
--
-- @param key  32-byte binary string
-- @param iv   16-byte binary string
-- @return context with :encrypt(plain) and :decrypt(cipher) methods
function M.new_context(key, iv)
  local W, Nr = keyExpand(key)
  local ctx = { _W=W, _Nr=Nr, _iv=iv }

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
-- Prefer new_context() when the same key is used more than once.
function M.encrypt(key, iv, plain)
  return M.new_context(key, iv):encrypt(plain)
end

--- AES-256-CBC decrypt (PKCS#7 padding removed automatically).
-- Prefer new_context() when the same key is used more than once.
function M.decrypt(key, iv, cipher)
  return M.new_context(key, iv):decrypt(cipher)
end

return M
