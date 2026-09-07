--[[
  unisenza.lua — Unisenza Plus gateway library for C-Bus / LogicMachine
  ======================================================================
  Handles AES-256-CBC encrypted JSON-over-HTTP communication with the
  local Unisenza Plus gateway (PUMG021GW).

  The Unisenza Plus system is an OEM of the Salus iT600 platform.

  Usage — resident poll (call from a thin script_resident_poll.lua)
  -----------------------------------------------------------------
    local unisenza = require("user.unisenza")
    unisenza.Resident_Poll({
      gateway_ip   = "192.168.1.59",
      gateway_euid = "001E5E090292DD94",
      cbus_network = 0,
      debug_param  = "Debug",
    })

  Usage — low-level API (for event scripts / direct control)
  ----------------------------------------------------------
    local unisenza = require("user.unisenza")
    local devices = unisenza.read_all()
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
-- CONFIGURATION DEFAULTS
-- These are used when calling the low-level API directly.
-- When calling Resident_Poll(config), values are taken from the config table.
-- ═════════════════════════════════════════════════════════════════════════════

-- IP address of the Unisenza Plus gateway on your LAN.
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

-- Cached AES context — created once on first use.
-- Holds the pre-expanded key schedule (60 round-key words) so keyExpand()
-- never runs more than once per controller restart, regardless of how many
-- polls or writes occur.
local _ctx = nil

-- ═════════════════════════════════════════════════════════════════════════════
-- CRYPTO HELPERS
-- ═════════════════════════════════════════════════════════════════════════════

local function get_ctx()
  if not _ctx then
    local ok, aes = pcall(require, "user.aes")
    if not ok then
      error("unisenza.lua requires aes.lua — load it as require('user.aes')", 2)
    end
    local key = aes.salus_key(M.GATEWAY_EUID)   -- MD5("Salus-"..euid)..zeros(16)
    local iv  = aes.hex2bin(IV_HEX)
    _ctx = aes.new_context(key, iv)             -- key schedule expanded here, once
  end
  return _ctx
end

-- ═════════════════════════════════════════════════════════════════════════════
-- JSON + HTTP  (module-level requires — both confirmed on 5500AC)
-- ═════════════════════════════════════════════════════════════════════════════

local json  = require("cjson")
local http  = require("socket.http")
local ltn12 = require("ltn12")

local function gateway_request(command, body_table)
  local ctx = get_ctx()   -- cached: key schedule never re-expanded after first call

  local url     = string.format("http://%s:%d/deviceid/%s",
                                 M.GATEWAY_IP, M.GATEWAY_PORT, command)
  local payload = json.encode(body_table)
  local cipher  = ctx:encrypt(payload)

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

  local plain = ctx:decrypt(table.concat(resp_chunks))
  return json.decode(plain)
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

-- ═════════════════════════════════════════════════════════════════════════════
-- RESIDENT POLL
-- Called once per sleep cycle from a thin script_resident_poll.lua script.
-- Matches the pattern used by cbus-ecowitt and other C-Bus Lua integrations.
-- ═════════════════════════════════════════════════════════════════════════════

-- Module-level state persisted between poll cycles
local _known_devices  = nil   -- nil = first run
local _missing_warned = {}

-- Device metadata cache shared with event scripts via a Lua global
unisenza_device_cache = unisenza_device_cache or {}

--- Single poll iteration — call this from your resident script each sleep cycle.
-- @param config table:
--   .gateway_ip    string   IP address of the gateway (overrides M.GATEWAY_IP)
--   .gateway_euid  string   EUID from gateway sticker (overrides M.GATEWAY_EUID)
--   .cbus_network  number   C-Bus network number for user params (default 0)
--   .debug_param   string   name of the boolean debug user param (default "Debug")
--   .debug         boolean  explicit debug override (default false)
function M.Resident_Poll(config)
  config = config or {}

  -- Apply config overrides
  if config.gateway_ip   then M.GATEWAY_IP   = config.gateway_ip   end
  if config.gateway_euid then M.GATEWAY_EUID = config.gateway_euid; _ctx = nil end

  local net        = config.cbus_network or 0
  local debug_param = config.debug_param or "Debug"

  -- Resolve debug flag: explicit override, or read from user param
  local dbg = config.debug or false
  if not dbg then
    local ok, v = pcall(GetUserParam, net, debug_param)
    dbg = ok and v == true
  end

  -- Safe write helper (local to this call, uses closure over net)
  local function safe_set(name, value)
    if value == nil then return end
    local ok = pcall(SetUserParam, net, name, value)
    if not ok then
      local key = net .. ":" .. name
      if dbg or not _missing_warned[key] then
        log("UNISENZA: UserParam '" .. name .. "' not found on network "
            .. tostring(net) .. " — skipping")
        _missing_warned[key] = true
      end
    end
  end

  if dbg then log("UNISENZA: polling gateway " .. M.GATEWAY_IP) end

  -- Fetch all devices
  local ok, devices = pcall(M.read_all)
  if not ok or not devices then
    local err = tostring(ok and "nil response" or devices)
    log("UNISENZA: poll failed — " .. err)
    safe_set("Unisenza_Status", "ERROR: " .. err)
    return
  end

  local ts = os.date("%d %b %Y %H:%M:%S")

  -- First-run discovery log
  if _known_devices == nil then
    log("UNISENZA: discovered " .. #devices .. " device(s) on gateway " .. M.GATEWAY_IP)
    for _, dev in ipairs(devices) do
      log(string.format("UNISENZA:   %-16s uid=%s", dev.name, dev.uid))
    end
    _known_devices = {}
    for _, dev in ipairs(devices) do _known_devices[dev.uid] = true end
  else
    local current = {}
    for _, dev in ipairs(devices) do current[dev.uid] = dev.name end
    for uid, name in pairs(current) do
      if not _known_devices[uid] then
        log("UNISENZA: new device — " .. name .. " (" .. uid .. ")")
        _known_devices[uid] = true
      end
    end
    for uid in pairs(_known_devices) do
      if not current[uid] then
        log("UNISENZA: device gone — uid=" .. uid)
        _known_devices[uid] = nil
      end
    end
  end

  -- Update device metadata cache for event scripts
  for _, dev in ipairs(devices) do
    unisenza_device_cache[dev.name] = dev
  end

  -- Write params for every discovered device
  local lines = {}
  for _, dev in ipairs(devices) do
    local name      = dev.name
    local temp_x10  = math.floor(dev.temp  * 10 + 0.5)
    local setpt_x10 = math.floor(dev.setpt * 10 + 0.5)

    safe_set(name .. "_CurrentTemp", temp_x10)
    safe_set(name .. "_Setpoint",    setpt_x10)
    safe_set(name .. "_HoldType",    dev.hold)
    safe_set(name .. "_Demand",      dev.demand)
    safe_set(name .. "_Online",      dev.online)

    if dbg then
      lines[#lines+1] = string.format(
        "  %-14s  %5.1f°C → %5.1f°C  %-10s  %3d%%  %s",
        name, dev.temp, dev.setpt,
        M.HOLD_NAMES[dev.hold] or tostring(dev.hold),
        dev.demand,
        dev.online == 1 and "online" or "OFFLINE"
      )
    end
  end

  safe_set("Unisenza_Status",      "OK")
  safe_set("Unisenza_LastUpdated", ts)
  safe_set("Unisenza_DeviceCount", #devices)

  if dbg then
    log("UNISENZA: ─── " .. ts .. " (" .. #devices .. " device(s)) ───")
    for _, line in ipairs(lines) do log(line) end
  end
end

return M
