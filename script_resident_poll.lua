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
  Debug                   boolean  true = verbose logging, false = silent
  Unisenza_Status         string   last poll result ("OK" or error)
  Unisenza_LastUpdated    string   timestamp of last successful poll
  Unisenza_DeviceCount    number   number of radiators discovered

  Per device (NAME = exact device name from app, e.g. "Romy"):
    NAME_CurrentTemp   float    room temp in °C  (e.g. 14.2)
    NAME_Setpoint      float    setpoint in °C   (e.g. 21.5) — writable
    NAME_HoldType      number   0=Schedule 2=Hold 7=Off 10=Eco
    NAME_Demand        number   heating demand 0–100 %
    NAME_Online        number   1=online 0=offline
--]]

local unisenza = require("user.unisenza")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================
local config = {
  gateway_ip   = "192.168.1.59",        -- LAN IP of the Unisenza Plus gateway
  gateway_euid = "001E5E090292DD94",    -- EUID from sticker on gateway hardware
  cbus_network = 0,                     -- C-Bus network number for user params
  debug_param  = "Debug",               -- Standard debug param name across all C-Bus scripts
  debug        = false,                 -- Set true to force debug on always
}

-- Execute single poll iteration
unisenza.Resident_Poll(config)
