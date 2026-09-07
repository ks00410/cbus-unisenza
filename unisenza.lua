--[[
  unisenza.lua — Unisenza Plus gateway API for C-Bus / LogicMachine Lua
  ======================================================================
  Handles AES-256-CBC encrypted JSON-over-HTTP communication with the
  local Unisenza Plus gateway (PUMG021GW).

  The Unisenza Plus system is an OEM of the Salus iT600 platform.

  Usage
  -----
    local unisenza = require("unisenza")

    local devices = unisenza.read_all()
    -- returns list of device tables (see Device fields below)
    -- devices are auto-discovered from the gateway — no config required.

    unisenza.set_temperature(device, 21.5)
    unisenza.set_hold(device, unisenza.HOLD_SCHEDULE)

  Device table fields
  -------------------
    .name       string   display name (from app)
    .uid        string   unique device ID (hex)
    .data       table    raw {DeviceType, Endpoint, UniID} — needed for writes
    .temp       number   current room temperature in °C
    .setpt      number   current heating setpoint in °C
    .hold       number   current HoldType (see HOLD_* constants)
    .online     number   1 = online, 0 = offline
    .demand     number   heating demand percentage (0–100)
    .min_sp     number   minimum allowed setpoint in °C
    .max_sp     number   maximum allowed setpoint in °C

  HoldType constants
  ------------------
    unisenza.HOLD_SCHEDULE   = 0   follow heating schedule
    unisenza.HOLD_TEMPORARY  = 1   temporary override
    unisenza.HOLD_PERMANENT  = 2   permanent hold at setpoint
    unisenza.HOLD_OFF        = 7   radiator off (frost protection)
    unisenza.HOLD_ECO        = 10  eco / setback mode
--]]

-- ═════════════════════════════════════════════════════════════════════════════
-- MODULE
-- ═════════════════════════════════════════════════════════════════════════════

local M = {}

-- ═════════════════════════════════════════════════════════════════════════════
-- CONFIGURATION  — edit these to match your installation
-- ═════════════════════════════════════════════════════════════════════════════

-- IP address of the Unisenza Plus gateway on your LAN.
-- Check your router's DHCP table or the Unisenza app for this value.
M.GATEWAY_IP   = "192.168.1.59"
M.GATEWAY_PORT = 80

-- EUID printed on the sticker on the gateway hardware (case-insensitive).
M.GATEWAY_EUID = "001E5E090292DD94"

-- Fixed IV used by the Unisenza Plus protocol (do not change)
local IV_HEX = "88a6b0795d85dbfce6e0b3e9a629654b"

-- ═════════════════════════════════════════════════════════════════════════════
-- HOLD TYPE CONSTANTS
-- ═════════════════════════════════════════════════════════════════════════════

M.HOLD_SCHEDULE  = 0
M.HOLD_TEMPORARY = 1
M.HOLD_PERMANENT = 2
M.HOLD_OFF       = 7
M.HOLD_ECO       = 10

M.HOLD_NAMES = {
  [0]  = "Schedule",
  [1]  = "Temp hold",
  [2]  = "Hold",
  [7]  = "Off",
  [10] = "Eco",
}

-- ═════════════════════════════════════════════════════════════════════════════
-- MODULE STATE
-- ═════════════════════════════════════════════════════════════════════════════

local _key = nil   -- cached 32-byte binary AES key (derived once on first use)
local _iv  = nil   -- cached 16-byte binary IV

-- ═════════════════════════════════════════════════════════════════════════════
-- CRYPTO HELPERS
-- ═════════════════════════════════════════════════════════════════════════════

local function get_aes()
  local ok, aes = pcall(require, "aes")
  if not ok then
    error("unisenza.lua requires aes.lua — load it first with require", 2)
  end
  return aes
end

local function get_key_iv()
  if not _key then
    local aes = get_aes()
    _key = aes.salus_key(M.GATEWAY_EUID)   -- key derivation: MD5("Salus-"..euid)..zeros
    _iv  = aes.hex2bin(IV_HEX)
  end
  return _key, _iv
end

-- ═════════════════════════════════════════════════════════════════════════════
-- JSON  (minimal — enough for our payloads)
-- ═════════════════════════════════════════════════════════════════════════════
-- LogicMachine / 5500AC does not guarantee a built-in json library.
-- We use a minimal encoder for the small outgoing payloads, and a pure-Lua
-- decoder for the gateway responses.

local function json_encode(v)
  local t = type(v)
  if     t == "nil"     then return "null"
  elseif t == "boolean" then return tostring(v)
  elseif t == "number"  then
    if v == math.floor(v) then return string.format("%d", v)
    else return string.format("%g", v) end
  elseif t == "string"  then
    return '"' .. v:gsub('\\','\\\\'):gsub('"','\\"')
                   :gsub('\n','\\n'):gsub('\r','\\r') .. '"'
  elseif t == "table" then
    local is_arr = true
    local max = 0
    for k in pairs(v) do
      if type(k) ~= "number" or k ~= math.floor(k) or k < 1 then
        is_arr = false; break
      end
      if k > max then max = k end
    end
    if is_arr and max == #v then
      local parts = {}
      for _, val in ipairs(v) do parts[#parts+1] = json_encode(val) end
      return "[" .. table.concat(parts, ",") .. "]"
    else
      local parts = {}
      for k, val in pairs(v) do
        parts[#parts+1] = json_encode(tostring(k)) .. ":" .. json_encode(val)
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
  end
  return "null"
end

local function json_decode(s)
  local pos = 1

  local function skip_ws()
    pos = s:match("^%s*()", pos)
  end

  local function decode_val()
    skip_ws()
    local c = s:sub(pos, pos)

    if c == '"' then
      pos = pos + 1
      local result = {}
      while true do
        local ch = s:sub(pos, pos)
        if ch == '"' then pos = pos + 1; break
        elseif ch == '\\' then
          pos = pos + 1
          local esc = s:sub(pos, pos)
          pos = pos + 1
          if     esc == '"'  then result[#result+1] = '"'
          elseif esc == '\\' then result[#result+1] = '\\'
          elseif esc == '/'  then result[#result+1] = '/'
          elseif esc == 'n'  then result[#result+1] = '\n'
          elseif esc == 'r'  then result[#result+1] = '\r'
          elseif esc == 't'  then result[#result+1] = '\t'
          else result[#result+1] = esc end
        else
          result[#result+1] = ch
          pos = pos + 1
        end
      end
      return table.concat(result)

    elseif c == '{' then
      pos = pos + 1
      local obj = {}
      skip_ws()
      if s:sub(pos,pos) == '}' then pos = pos + 1; return obj end
      while true do
        skip_ws()
        local key = decode_val()
        skip_ws()
        pos = pos + 1   -- skip ':'
        local val = decode_val()
        obj[key] = val
        skip_ws()
        local sep = s:sub(pos,pos)
        pos = pos + 1
        if sep == '}' then break end
      end
      return obj

    elseif c == '[' then
      pos = pos + 1
      local arr = {}
      skip_ws()
      if s:sub(pos,pos) == ']' then pos = pos + 1; return arr end
      while true do
        arr[#arr+1] = decode_val()
        skip_ws()
        local sep = s:sub(pos,pos)
        pos = pos + 1
        if sep == ']' then break end
      end
      return arr

    elseif c == 't' then pos = pos + 4; return true
    elseif c == 'f' then pos = pos + 5; return false
    elseif c == 'n' then pos = pos + 4; return nil

    else
      local num_str = s:match("^%-?%d+%.?%d*[eE]?[+-]?%d*", pos)
      pos = pos + #num_str
      return tonumber(num_str)
    end
  end

  return decode_val()
end

-- ═════════════════════════════════════════════════════════════════════════════
-- HTTP REQUEST
-- ═════════════════════════════════════════════════════════════════════════════

local function gateway_request(command, body_table)
  local aes = get_aes()
  local key, iv = get_key_iv()

  local url     = string.format("http://%s:%d/deviceid/%s",
                                 M.GATEWAY_IP, M.GATEWAY_PORT, command)
  local payload = json_encode(body_table)
  local cipher  = aes.encrypt(key, iv, payload)

  local http  = require("socket.http")
  local ltn12 = require("ltn12")

  local resp_chunks = {}
  local _, code = http.request({
    url     = url,
    method  = "POST",
    headers = {
      ["Content-Type"]   = "application/json",
      ["Content-Length"] = tostring(#cipher),
    },
    source = ltn12.source.string(cipher),
    sink   = ltn12.sink.table(resp_chunks),
  })

  if code ~= 200 then
    log("UNISENZA: HTTP error " .. tostring(code) .. " for " .. url)
    return nil
  end

  local plain = aes.decrypt(key, iv, table.concat(resp_chunks))
  return json_decode(plain)
end

-- ═════════════════════════════════════════════════════════════════════════════
-- DEVICE PARSING
-- ═════════════════════════════════════════════════════════════════════════════

local function parse_name(d)
  local ok, name_str = pcall(function()
    return d.sZDO and d.sZDO.DeviceName or nil
  end)
  if not ok or not name_str then return d.data and d.data.UniID or "unknown" end
  -- sZDO.DeviceName is itself JSON: {"deviceName":"Romy","ShortID_d":7674}
  local name = name_str:match('"deviceName"%s*:%s*"([^"]+)"')
  return name or (d.data and d.data.UniID or "unknown")
end

local function parse_device(d)
  local ther  = d.sTherS
  local scomm = d.sComm
  if not ther or not scomm then return nil end

  local raw_sp = ther.HeatingSetpoint_x100 or 0
  -- Large negative sentinels (e.g. -17.77°C) indicate frost/off mode.
  -- Fall back to PermanentHeatingSetpoint which holds the last real setpoint.
  local setpt
  if raw_sp > -1000 then
    setpt = raw_sp / 100
  else
    setpt = (scomm.PermanentHeatingSetpoint or 0) / 100
  end

  return {
    name   = parse_name(d),
    uid    = d.data and d.data.UniID or "?",
    data   = d.data,                           -- needed verbatim for writes
    temp   = (ther.LocalTemperature_x100 or 0) / 100,
    setpt  = setpt,
    hold   = scomm.HoldType or 0,
    online = (d.sZDOInfo and d.sZDOInfo.OnlineStatus_i) or 0,
    demand = ther.HeatingDemandInPtg or 0,
    min_sp = (ther.MinHeatSetpoint_x100 or  500) / 100,
    max_sp = (ther.MaxHeatSetpoint_x100 or 3000) / 100,
  }
end

-- ═════════════════════════════════════════════════════════════════════════════
-- PUBLIC READ API
-- ═════════════════════════════════════════════════════════════════════════════

--- Fetch all thermostat devices from the gateway (auto-discovered).
-- No device list configuration is required — every sTherS device found on
-- the gateway is returned.
-- @return array of device tables sorted by name, or nil on error.
function M.read_all()
  local result = gateway_request("read", { requestAttr = "readall" })
  if not result then return nil end

  local devices = {}
  for _, d in ipairs(result.id or {}) do
    local dev = parse_device(d)
    if dev then devices[#devices+1] = dev end
  end

  table.sort(devices, function(a, b) return a.name < b.name end)
  return devices
end

-- ═════════════════════════════════════════════════════════════════════════════
-- PUBLIC WRITE API
-- ═════════════════════════════════════════════════════════════════════════════

--- Set the heating setpoint and switch to permanent hold.
-- @param device   device table (must include .data field)
-- @param celsius  number  desired setpoint °C (rounded to nearest 0.5°C)
-- @return true on success, nil on error
function M.set_temperature(device, celsius)
  celsius = math.floor(celsius * 2 + 0.5) / 2
  celsius = math.max(device.min_sp, math.min(device.max_sp, celsius))

  local result = gateway_request("write", {
    requestAttr = "write",
    id = {{
      data   = device.data,
      sTherS = { SetHeatingSetpoint_x100 = math.floor(celsius * 100) },
      sComm  = { SetHoldType = M.HOLD_PERMANENT },
    }}
  })

  if result and result.status == "success" then
    device.setpt = celsius
    device.hold  = M.HOLD_PERMANENT
    return true
  end
  return nil
end

--- Set the hold type without changing the setpoint.
-- @param device     device table
-- @param hold_type  number  one of the M.HOLD_* constants
-- @return true on success, nil on error
function M.set_hold(device, hold_type)
  local result = gateway_request("write", {
    requestAttr = "write",
    id = {{
      data  = device.data,
      sComm = { SetHoldType = hold_type },
    }}
  })

  if result and result.status == "success" then
    device.hold = hold_type
    return true
  end
  return nil
end

return M
