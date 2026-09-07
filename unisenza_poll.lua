--[[
  unisenza_poll.lua — C-Bus / LogicMachine Resident Script
  =========================================================
  Polls the Unisenza Plus gateway every POLL_INTERVAL seconds and writes
  each radiator's live state into C-Bus User Parameters.  Devices are
  auto-discovered from the gateway — no static device list needed.

  On each successful poll the script logs all discovered devices and writes
  their state.  The first poll also logs a discovery summary showing every
  device found, matching the pattern used across C-Bus Lua scripts.

  Install on the 5500AC (LogicMachine)
  -------------------------------------
  1. Upload aes.lua and unisenza.lua as Lua libraries
     (Scripting → Lua libraries in the LogicMachine web UI).
  2. Create a Resident Script, paste this file, set Sleep time = 1 second.
  3. Create the User Parameters listed below for each discovered device.
  4. Set Unisenza_Debug = 1 to see the first-run discovery log.

  User Parameters  (network = CBUS_NETWORK below)
  -----------------------------------------------
  Unisenza_Debug          number   0 = silent, 1 = verbose logging
  Unisenza_Status         string   last poll result ("OK" or error)
  Unisenza_LastUpdated    string   timestamp of last successful poll
  Unisenza_DeviceCount    number   number of radiators currently visible

  Per device (NAME = device name from app, e.g. "Romy"):
    NAME_CurrentTemp   number   room temp ×10  (142 = 14.2 °C)
    NAME_Setpoint      number   setpoint ×10   (215 = 21.5 °C)
    NAME_HoldType      number   0=Schedule 2=Hold 7=Off 10=Eco
    NAME_Demand        number   heating demand 0–100 %
    NAME_Online        number   1=online 0=offline

  Temperatures ×10: C-Bus user params are integers. Divide by 10 to display.
--]]

-- ═════════════════════════════════════════════════════════════════════════════
-- CONFIGURATION
-- ═════════════════════════════════════════════════════════════════════════════

-- Seconds between gateway queries (gateway caches; <30 s gains nothing)
local POLL_INTERVAL = 30

-- C-Bus network number holding the User Parameters (0 = default local network)
local CBUS_NETWORK = 0

-- ═════════════════════════════════════════════════════════════════════════════
-- MODULE STATE
-- ═════════════════════════════════════════════════════════════════════════════

local _last_poll      = 0      -- os.time() of last successful poll
local _known_devices  = nil    -- set on first successful poll; nil = not yet run
local _missing_warned = {}     -- suppress repeated "param not found" warnings

-- ═════════════════════════════════════════════════════════════════════════════
-- LOGGING HELPERS
-- ═════════════════════════════════════════════════════════════════════════════

local function is_debug()
  local ok, v = pcall(GetUserParam, CBUS_NETWORK, "Unisenza_Debug")
  return ok and (tonumber(v) or 0) == 1
end

local function dbglog(msg, dbg)
  if dbg then log("UNISENZA_POLL: " .. tostring(msg)) end
end

-- ═════════════════════════════════════════════════════════════════════════════
-- C-BUS I/O HELPERS
-- ═════════════════════════════════════════════════════════════════════════════

local function safe_set(name, value, dbg)
  if value == nil then return end
  local ok = pcall(SetUserParam, CBUS_NETWORK, name, value)
  if not ok then
    local key = CBUS_NETWORK .. ":" .. name
    if dbg or not _missing_warned[key] then
      log("UNISENZA_POLL: UserParam '" .. name
          .. "' not found on network " .. CBUS_NETWORK .. " — skipping")
      _missing_warned[key] = true
    end
  end
end

-- ═════════════════════════════════════════════════════════════════════════════
-- RESIDENT POLL ENTRY POINT
-- ═════════════════════════════════════════════════════════════════════════════

function E.Resident_Poll()
  -- ── rate-limit ─────────────────────────────────────────────────────────────
  local now = os.time()
  if (now - _last_poll) < POLL_INTERVAL then return end
  _last_poll = now

  local dbg = is_debug()

  -- ── query gateway (auto-discovers all devices) ─────────────────────────────
  local unisenza = require("unisenza")
  local ok, result = pcall(unisenza.read_all)

  if not ok or not result then
    local err = tostring(ok and "nil response" or result)
    log("UNISENZA_POLL: error — " .. err)
    safe_set("Unisenza_Status", "ERROR: " .. err, dbg)
    return
  end

  local ts = os.date("%d %b %Y %H:%M:%S")

  -- ── first-run discovery log ────────────────────────────────────────────────
  if _known_devices == nil then
    log("UNISENZA_POLL: discovered " .. #result .. " device(s) on gateway "
        .. unisenza.GATEWAY_IP)
    for _, dev in ipairs(result) do
      log(string.format(
        "UNISENZA_POLL:   %-16s uid=%-20s model=%s",
        dev.name, dev.uid,
        dev.data and tostring(dev.data.DeviceType) or "?"
      ))
    end
    _known_devices = {}
    for _, dev in ipairs(result) do _known_devices[dev.uid] = true end
  else
    -- Log any newly appeared or disappeared devices
    local current = {}
    for _, dev in ipairs(result) do current[dev.uid] = dev.name end
    for uid, name in pairs(current) do
      if not _known_devices[uid] then
        log("UNISENZA_POLL: new device appeared — " .. name .. " (" .. uid .. ")")
        _known_devices[uid] = true
      end
    end
    for uid in pairs(_known_devices) do
      if not current[uid] then
        log("UNISENZA_POLL: device disappeared — uid=" .. uid)
        _known_devices[uid] = nil
      end
    end
  end

  -- ── write params for every discovered device ───────────────────────────────
  local lines = {}

  for _, dev in ipairs(result) do
    local name      = dev.name
    local temp_x10  = math.floor(dev.temp  * 10 + 0.5)
    local setpt_x10 = math.floor(dev.setpt * 10 + 0.5)

    safe_set(name .. "_CurrentTemp", temp_x10,  dbg)
    safe_set(name .. "_Setpoint",    setpt_x10, dbg)
    safe_set(name .. "_HoldType",    dev.hold,   dbg)
    safe_set(name .. "_Demand",      dev.demand, dbg)
    safe_set(name .. "_Online",      dev.online, dbg)

    if dbg then
      lines[#lines+1] = string.format(
        "  %-14s  %5.1f°C → %5.1f°C  %-10s  %3d%%  %s",
        name, dev.temp, dev.setpt,
        unisenza.HOLD_NAMES[dev.hold] or tostring(dev.hold),
        dev.demand,
        dev.online == 1 and "online" or "OFFLINE"
      )
    end
  end

  -- ── global status ──────────────────────────────────────────────────────────
  safe_set("Unisenza_Status",      "OK",      dbg)
  safe_set("Unisenza_LastUpdated", ts,        dbg)
  safe_set("Unisenza_DeviceCount", #result,   dbg)

  if dbg then
    log("UNISENZA_POLL: ─── " .. ts .. " (" .. #result .. " device(s)) ───")
    for _, line in ipairs(lines) do log(line) end
  end
end
