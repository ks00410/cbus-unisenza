--[[
  script_resident_poll.lua — Unisenza Plus Resident Poll Script
  =============================================================
  Script Type: Resident Script
  Sleep interval: 30 seconds

  Polls the Unisenza Plus gateway once per sleep cycle and writes each
  radiator's live state into C-Bus User Parameters.  Devices are
  auto-discovered — no static list required.

  C-Bus User Parameters to create:
  ---------------------------------
  Unisenza_Debug          number   1 = verbose logging, 0 = silent
  Unisenza_Status         string   last poll result ("OK" or error)
  Unisenza_LastUpdated    string   timestamp of last successful poll
  Unisenza_DeviceCount    number   number of radiators discovered

  Per device (NAME = exact device name from app, e.g. "Romy"):
    NAME_CurrentTemp   number   room temp ×10  (142 = 14.2 °C)
    NAME_Setpoint      number   setpoint ×10   (215 = 21.5 °C)
    NAME_HoldType      number   0=Schedule 2=Hold 7=Off 10=Eco
    NAME_Demand        number   heating demand 0–100 %
    NAME_Online        number   1=online 0=offline
--]]

local unisenza = require("unisenza")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================
local config = {
  gateway_ip   = "192.168.1.59",        -- LAN IP of the Unisenza Plus gateway
  gateway_euid = "001E5E090292DD94",    -- EUID from sticker on gateway hardware
  cbus_network = 0,                     -- C-Bus network number for user params
  debug_param  = "Unisenza_Debug",      -- User param name for debug toggle
  debug        = false,                 -- Set true to force debug on always
}

-- Execute single poll iteration
unisenza.Resident_Poll(config)
