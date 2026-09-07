--[[
  unisenza_set.lua — C-Bus / LogicMachine Event Script
  =====================================================
  Triggered whenever any radiator's _Setpoint or _HoldType user parameter
  is changed (e.g. by a touch panel, rule, or another script).  Reads the
  changed value, finds the matching device on the gateway, and pushes the
  update.

  Install on the 5500AC (LogicMachine)
  -------------------------------------
  1. Make sure aes.lua and unisenza.lua are uploaded as Lua libraries.
  2. Create one Event Script per radiator, named e.g. "Unisenza Set Romy".
  3. Paste this file as the body.
  4. Set RADIATOR_NAME at the top to the device's exact name (as shown in
     the Unisenza app and discovered by unisenza_poll.lua).
  5. Set the trigger to: User Parameter changed → NAME_Setpoint
     (or NAME_HoldType if you also want mode buttons to trigger this script).

  How setpoint control works
  --------------------------
  Touch panel or rule writes an integer to NAME_Setpoint (temperature ×10,
  e.g. 215 = 21.5 °C).  This script converts it back to °C, locates the
  device via the gateway's readall response, and calls set_temperature(),
  which also automatically switches the device to permanent hold.

  How hold-type control works
  ---------------------------
  Write to NAME_HoldType with one of:
    0  = follow schedule
    2  = permanent hold (use NAME_Setpoint for the temperature)
    7  = off (frost protection)
    10 = eco mode
  If HoldType ≠ 2 (permanent hold), only the mode is sent and the setpoint
  on the device is left unchanged.
--]]

-- ═════════════════════════════════════════════════════════════════════════════
-- CONFIGURATION — set this for each copy of the script
-- ═════════════════════════════════════════════════════════════════════════════

-- Exact device name as it appears in the Unisenza app (and in the poll log).
-- Clone this script for each radiator, changing only this line.
local RADIATOR_NAME = "Romy"   -- e.g. "Garage", "Finn"

-- C-Bus network number holding the User Parameters
local CBUS_NETWORK = 0

-- ═════════════════════════════════════════════════════════════════════════════
-- LOGGING HELPERS
-- ═════════════════════════════════════════════════════════════════════════════

local function is_debug()
  local ok, v = pcall(GetUserParam, CBUS_NETWORK, "Unisenza_Debug")
  return ok and (tonumber(v) or 0) == 1
end

local function dbglog(msg, dbg)
  if dbg then log("UNISENZA_SET [" .. RADIATOR_NAME .. "]: " .. tostring(msg)) end
end

-- ═════════════════════════════════════════════════════════════════════════════
-- EVENT ENTRY POINT
-- ═════════════════════════════════════════════════════════════════════════════

function E.Event()
  local dbg      = is_debug()
  local unisenza = require("unisenza")

  -- ── read the current setpoint and hold type from params ───────────────────
  local ok_sp, raw_sp = pcall(GetUserParam, CBUS_NETWORK,
                               RADIATOR_NAME .. "_Setpoint")
  local ok_ht, raw_ht = pcall(GetUserParam, CBUS_NETWORK,
                               RADIATOR_NAME .. "_HoldType")

  local setpt_x10 = ok_sp and tonumber(raw_sp) or nil
  local hold_type = ok_ht and tonumber(raw_ht) or nil

  -- ── find the device — use cache populated by unisenza_poll.lua ────────────
  -- unisenza_device_cache is a global written by the resident poll script on
  -- every successful read.  Using it avoids a redundant read_all() HTTP call
  -- on every write event.  Falls back to read_all() only if the cache is cold
  -- (e.g. the first write fires before the first poll has completed).
  local target = unisenza_device_cache and unisenza_device_cache[RADIATOR_NAME]

  if not target then
    dbglog("cache cold — falling back to read_all()", dbg)
    local ok_read, devices = pcall(unisenza.read_all)
    if not ok_read or not devices then
      local err = tostring(ok_read and "nil response" or devices)
      log("UNISENZA_SET [" .. RADIATOR_NAME .. "]: read_all failed — " .. err)
      return
    end
    for _, dev in ipairs(devices) do
      if dev.name == RADIATOR_NAME then target = dev; break end
    end
  end

  if not target then
    log("UNISENZA_SET [" .. RADIATOR_NAME
        .. "]: device not found in gateway response or cache")
    return
  end

  -- ── push the change ───────────────────────────────────────────────────────
  -- If hold type is set to something other than permanent hold, send mode only.
  -- Otherwise send temperature (which also sets permanent hold).
  if hold_type ~= nil and hold_type ~= unisenza.HOLD_PERMANENT then
    local mode_name = unisenza.HOLD_NAMES[hold_type] or tostring(hold_type)
    dbglog("setting hold → " .. mode_name, dbg)
    local ok = unisenza.set_hold(target, hold_type)
    if not ok then
      log("UNISENZA_SET [" .. RADIATOR_NAME .. "]: set_hold failed")
      return
    end
    dbglog("hold set OK → " .. mode_name, dbg)

  elseif setpt_x10 ~= nil then
    local celsius = setpt_x10 / 10
    dbglog("setting temperature → " .. celsius .. " °C", dbg)
    local ok = unisenza.set_temperature(target, celsius)
    if not ok then
      log("UNISENZA_SET [" .. RADIATOR_NAME .. "]: set_temperature failed")
      return
    end
    dbglog("temperature set OK → " .. target.setpt .. " °C (hold)", dbg)
    -- Write confirmed (rounded) value back
    pcall(SetUserParam, CBUS_NETWORK,
          RADIATOR_NAME .. "_Setpoint",
          math.floor(target.setpt * 10 + 0.5))
    pcall(SetUserParam, CBUS_NETWORK,
          RADIATOR_NAME .. "_HoldType", unisenza.HOLD_PERMANENT)

  else
    dbglog("no actionable param value — nothing sent", dbg)
  end
end
