--[[
  salus_set.lua — C-Bus / LogicMachine Event Script
  ==================================================
  Triggered whenever a radiator's Setpoint user parameter is changed
  (e.g. by a touch panel, a rule, or another script).  Reads the new
  setpoint value and pushes it to the Salus gateway.

  Install on the 5500AC (LogicMachine)
  -------------------------------------
  1. Make sure aes.lua and salus.lua are uploaded as Lua libraries.
  2. Create one Event Script per radiator (or use a single script triggered
     by any of the _Setpoint params — see "Trigger" note below).
  3. Paste this file as the script body.  Set the trigger to:
       User Parameter changed: <NAME>_Setpoint
  4. Enable the script.

  How it works
  ------------
  When a touch panel (or rule) writes a new integer value to NAME_Setpoint
  (temperature ×10, e.g. 215 = 21.5 °C), this script fires, converts the
  value back to °C, finds the matching device from the gateway, and calls
  salus.set_temperature().  The gateway confirms with {"status":"success"}.

  The script also reads the optional NAME_HoldType param.  If it is set to
  a value other than HOLD_PERMANENT (2), it sends a hold-type-only write
  without changing the setpoint — useful for schedule/off/eco buttons.

  Configuration
  -------------
  Set RADIATOR_NAME below to match the C-Bus user param prefix AND the exact
  device name in the Salus app.  Clone this script for each radiator, changing
  only RADIATOR_NAME.
--]]

-- ═════════════════════════════════════════════════════════════════════════════
-- CONFIGURATION — change this for each radiator copy of the script
-- ═════════════════════════════════════════════════════════════════════════════

-- Must match both the Salus app device name AND the user param prefix.
local RADIATOR_NAME = "Romy"   -- e.g. "Garage", "Finn"

-- C-Bus network number that holds the User Parameters.
local CBUS_NETWORK = 0

-- ═════════════════════════════════════════════════════════════════════════════
-- LOGGING HELPERS
-- ═════════════════════════════════════════════════════════════════════════════

local function is_debug()
  local ok, v = pcall(GetUserParam, CBUS_NETWORK, "Salus_Debug")
  return ok and (tonumber(v) or 0) == 1
end

local function dbglog(msg, dbg)
  if dbg then log("SALUS_SET [" .. RADIATOR_NAME .. "]: " .. tostring(msg)) end
end

-- ═════════════════════════════════════════════════════════════════════════════
-- EVENT ENTRY POINT
-- ═════════════════════════════════════════════════════════════════════════════

function E.Event()
  local dbg   = is_debug()
  local salus = require("salus")

  -- ── read the newly written setpoint ────────────────────────────────────────
  local ok_sp, raw_sp = pcall(GetUserParam, CBUS_NETWORK,
                               RADIATOR_NAME .. "_Setpoint")
  if not ok_sp or raw_sp == nil then
    log("SALUS_SET [" .. RADIATOR_NAME .. "]: could not read _Setpoint param")
    return
  end

  local setpt_x10 = tonumber(raw_sp)
  if not setpt_x10 then
    log("SALUS_SET [" .. RADIATOR_NAME .. "]: _Setpoint value is not a number: "
        .. tostring(raw_sp))
    return
  end

  local celsius = setpt_x10 / 10
  dbglog("requested setpoint " .. celsius .. " °C", dbg)

  -- ── optionally read hold type ──────────────────────────────────────────────
  local hold_type = nil
  local ok_ht, raw_ht = pcall(GetUserParam, CBUS_NETWORK,
                                RADIATOR_NAME .. "_HoldType")
  if ok_ht and raw_ht ~= nil then
    hold_type = tonumber(raw_ht)
  end

  -- ── find the device on the gateway ────────────────────────────────────────
  local ok_read, devices = pcall(salus.read_all)
  if not ok_read or not devices then
    local err = tostring(ok_read and "nil response" or devices)
    log("SALUS_SET [" .. RADIATOR_NAME .. "]: read_all failed — " .. err)
    return
  end

  local target = nil
  for _, dev in ipairs(devices) do
    if dev.name == RADIATOR_NAME then
      target = dev
      break
    end
  end

  if not target then
    log("SALUS_SET [" .. RADIATOR_NAME
        .. "]: device not found in gateway response")
    return
  end

  -- ── decide what to write ─────────────────────────────────────────────────
  -- If hold type is being set to something other than permanent hold,
  -- only send the hold type (the setpoint stays unchanged on the device).
  if hold_type ~= nil and hold_type ~= salus.HOLD_PERMANENT then
    dbglog("setting hold type → " .. (salus.HOLD_NAMES[hold_type] or tostring(hold_type)), dbg)
    local ok_ht2 = salus.set_hold(target, hold_type)
    if not ok_ht2 then
      log("SALUS_SET [" .. RADIATOR_NAME .. "]: set_hold failed")
    else
      dbglog("hold type set OK", dbg)
    end
  else
    -- Normal path: set temperature (this also sets hold → PERMANENT)
    dbglog("setting temperature → " .. celsius .. " °C", dbg)
    local ok_set = salus.set_temperature(target, celsius)
    if not ok_set then
      log("SALUS_SET [" .. RADIATOR_NAME .. "]: set_temperature failed")
    else
      dbglog("temperature set OK", dbg)
      -- Write back confirmed setpoint (rounded by set_temperature)
      local confirmed_x10 = math.floor(target.setpt * 10 + 0.5)
      pcall(SetUserParam, CBUS_NETWORK,
            RADIATOR_NAME .. "_Setpoint", confirmed_x10)
      pcall(SetUserParam, CBUS_NETWORK,
            RADIATOR_NAME .. "_HoldType", salus.HOLD_PERMANENT)
    end
  end
end
