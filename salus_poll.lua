--[[
  salus_poll.lua — C-Bus / LogicMachine Resident Script
  ======================================================
  Polls the Salus / Unisenza Plus gateway every POLL_INTERVAL seconds and
  writes each radiator's live state into C-Bus User Parameters so they can
  be read by touch panels, rules, and other scripts.

  Install on the 5500AC (LogicMachine)
  -------------------------------------
  1. Upload aes.lua and salus.lua to the controller's Lua library store
     (Scripting → Lua libraries on the LogicMachine web UI).
  2. Create a new Resident Script (Scripting → Resident scripts), paste this
     file as the body, set Sleep time = 1 second.
  3. Create the User Parameters listed below in your C-Bus project.
  4. Enable the script.

  User Parameters required  (network = CBUS_NETWORK constant below)
  -----------------------------------------------------------------
  Salus_Debug          boolean / number   0 = off, 1 = verbose logging
  Salus_Status         string             last poll result
  Salus_LastUpdated    string             timestamp of last successful poll

  Per radiator (replace NAME with the exact device name, e.g. "Romy"):
    NAME_CurrentTemp   number   room temperature ×10 (142 = 14.2 °C)
    NAME_Setpoint      number   heating setpoint ×10 (215 = 21.5 °C)
    NAME_HoldType      number   0 schedule / 2 hold / 7 off / 10 eco
    NAME_Demand        number   heating demand 0–100 %
    NAME_Online        number   1 = online, 0 = offline

  Temperatures are stored ×10 as integers because C-Bus user params are
  integers or strings — not floats.  Divide by 10 wherever you display them.
--]]

-- ═════════════════════════════════════════════════════════════════════════════
-- CONFIGURATION
-- ═════════════════════════════════════════════════════════════════════════════

-- Seconds between gateway queries.  The gateway caches responses; querying
-- more often than 30 s wastes resources without gaining fresher data.
local POLL_INTERVAL = 30

-- C-Bus network number that holds the User Parameters.
-- 0 is the default local network on a LogicMachine / 5500AC.
local CBUS_NETWORK = 0

-- Exact radiator names as they appear in the Unisenza Plus / Salus app.
-- Add or remove entries to match your installation.
local RADIATORS = {
  "Romy",
  "Garage",
  "Finn",
}

-- ═════════════════════════════════════════════════════════════════════════════
-- MODULE STATE
-- ═════════════════════════════════════════════════════════════════════════════

local _last_poll      = 0      -- os.time() of last poll attempt
local _missing_warned = {}     -- suppress repeated "param not found" warnings

-- ═════════════════════════════════════════════════════════════════════════════
-- LOGGING HELPERS
-- ═════════════════════════════════════════════════════════════════════════════

local function is_debug()
  local ok, v = pcall(GetUserParam, CBUS_NETWORK, "Salus_Debug")
  return ok and (tonumber(v) or 0) == 1
end

local function dbglog(msg, dbg)
  if dbg then log("SALUS_POLL: " .. tostring(msg)) end
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
      log("SALUS_POLL: UserParam '" .. name
          .. "' not found on network " .. CBUS_NETWORK .. " — skipping")
      _missing_warned[key] = true
    end
  end
end

-- ═════════════════════════════════════════════════════════════════════════════
-- RESIDENT POLL ENTRY POINT
-- ═════════════════════════════════════════════════════════════════════════════

function E.Resident_Poll()
  -- ── rate-limit: only poll every POLL_INTERVAL seconds ─────────────────────
  local now = os.time()
  if (now - _last_poll) < POLL_INTERVAL then return end
  _last_poll = now

  local dbg = is_debug()
  dbglog("polling gateway", dbg)

  -- ── query the gateway ──────────────────────────────────────────────────────
  -- salus.lua is a LogicMachine Lua library — require() loads it.
  local salus = require("salus")

  local ok, result = pcall(salus.read_all)
  if not ok or not result then
    local err = tostring(ok and "nil response" or result)
    log("SALUS_POLL: error — " .. err)
    safe_set("Salus_Status", "ERROR: " .. err, dbg)
    return
  end

  -- ── index devices by name ─────────────────────────────────────────────────
  local by_name = {}
  for _, dev in ipairs(result) do
    by_name[dev.name] = dev
  end

  -- ── write params for each radiator ────────────────────────────────────────
  local ts    = os.date("%d %b %Y %H:%M:%S")
  local lines = {}   -- collected for debug output

  for _, name in ipairs(RADIATORS) do
    local dev = by_name[name]
    if dev then
      -- Multiply by 10 and round so temps fit in integer user params
      local temp_x10  = math.floor(dev.temp  * 10 + 0.5)
      local setpt_x10 = math.floor(dev.setpt * 10 + 0.5)

      safe_set(name .. "_CurrentTemp", temp_x10,  dbg)
      safe_set(name .. "_Setpoint",    setpt_x10, dbg)
      safe_set(name .. "_HoldType",    dev.hold,   dbg)
      safe_set(name .. "_Demand",      dev.demand, dbg)
      safe_set(name .. "_Online",      dev.online, dbg)

      if dbg then
        lines[#lines+1] = string.format(
          "  %-12s  %5.1f°C → %5.1f°C  %-10s  demand=%3d%%  %s",
          name, dev.temp, dev.setpt,
          salus.HOLD_NAMES[dev.hold] or tostring(dev.hold),
          dev.demand,
          dev.online == 1 and "online" or "OFFLINE"
        )
      end
    else
      dbglog("'" .. name .. "' not found in gateway response", dbg)
    end
  end

  -- ── update global status params ───────────────────────────────────────────
  safe_set("Salus_Status",      "OK", dbg)
  safe_set("Salus_LastUpdated", ts,   dbg)

  if dbg then
    log("SALUS_POLL: ─── " .. ts .. " ───")
    for _, line in ipairs(lines) do log(line) end
  end
end
