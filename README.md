# cbus-salus

C-Bus / LogicMachine Lua scripts for controlling **Salus iT600 / Unisenza Plus** smart radiators from a Schneider Electric C-Bus SpaceLogic **5500AC** controller (LogicMachine OEM).

Communicates directly with the local Salus gateway over your LAN — no cloud, no internet required.

---

## How it works

The Salus/Unisenza Plus gateway exposes a local HTTP API on port 80.  All requests and responses are **AES-256-CBC encrypted JSON**, with the key derived from the gateway's EUID (printed on the sticker).  These scripts implement that protocol entirely in pure Lua — no external libraries or packages needed.

```
5500AC controller
  └── salus_poll.lua  (resident, every 30 s)
        └── salus.lua → HTTP POST /deviceid/read → gateway (192.168.x.x)
              └── aes.lua  (pure-Lua AES-256-CBC + MD5)

  └── salus_set.lua  (event, on _Setpoint param change)
        └── salus.lua → HTTP POST /deviceid/write → gateway
```

---

## Files

| File | Type | Purpose |
|---|---|---|
| [`aes.lua`](aes.lua) | Lua library | Pure-Lua AES-256-CBC encrypt/decrypt + MD5. No dependencies. |
| [`salus.lua`](salus.lua) | Lua library | Gateway API: `read_all()`, `set_temperature()`, `set_hold()` |
| [`salus_poll.lua`](salus_poll.lua) | Resident script | Polls gateway every 30 s, writes state to C-Bus user params |
| [`salus_set.lua`](salus_set.lua) | Event script | Fires when a `_Setpoint` param changes; pushes new setpoint to gateway |

---

## Installation

### 1. Find your gateway EUID

The EUID is on the sticker on the **Unisenza Plus / Salus iT600 gateway** (model PUMG021GW).  It looks like `001E5E090292DD94`.

### 2. Configure `salus.lua`

Edit the top of [`salus.lua`](salus.lua):

```lua
M.GATEWAY_IP   = "192.168.1.59"   -- IP address of your gateway
M.GATEWAY_EUID = "001E5E090292DD94"  -- EUID from gateway sticker
```

Find the gateway IP on your router's DHCP table, or from the Unisenza Plus app.

### 3. Configure `salus_poll.lua`

Edit the `RADIATORS` table to match your device names (exactly as they appear in the Salus/Unisenza app):

```lua
local RADIATORS = {
  "Romy",
  "Garage",
  "Finn",
}
```

### 4. Upload libraries to the 5500AC

In the LogicMachine web UI:
- Go to **Scripting → Lua libraries**
- Upload `aes.lua` and `salus.lua`

### 5. Create the resident poll script

- Go to **Scripting → Resident scripts → Add new**
- Name: `Salus Poll`
- Sleep time: `1` second (the script rate-limits itself to 30 s internally)
- Paste the contents of `salus_poll.lua` as the body
- Enable the script

### 6. Create event scripts (one per radiator)

For each radiator (e.g. "Romy"):
- Go to **Scripting → Event scripts → Add new**
- Name: `Salus Set Romy`
- Trigger: **User Parameter changed** → `Romy_Setpoint`
- Set `local RADIATOR_NAME = "Romy"` at the top of the script
- Paste the contents of `salus_set.lua` as the body
- Enable the script

### 7. Create C-Bus User Parameters

Create these User Parameters on network `0` (or whichever network number you set in `CBUS_NETWORK`):

**Global:**
| Parameter | Type | Purpose |
|---|---|---|
| `Salus_Debug` | Number | Set to `1` for verbose logging, `0` for silent |
| `Salus_Status` | String | Last poll result (`OK` or error message) |
| `Salus_LastUpdated` | String | Timestamp of last successful poll |

**Per radiator** (repeat for each, replacing `NAME`):
| Parameter | Type | Notes |
|---|---|---|
| `NAME_CurrentTemp` | Number | Room temp ×10 (142 = 14.2 °C) |
| `NAME_Setpoint` | Number | Setpoint ×10 (215 = 21.5 °C) — **write this to control the radiator** |
| `NAME_HoldType` | Number | 0=Schedule, 2=Hold, 7=Off, 10=Eco |
| `NAME_Demand` | Number | Heating demand 0–100 % |
| `NAME_Online` | Number | 1=online, 0=offline |

> **Why ×10?**  C-Bus user parameters are integers or strings — not floats.  Multiply by 10 so 21.5 °C is stored as `215`.  Divide by 10 in any display rule.

---

## Controlling a radiator

To set a radiator's temperature from a C-Bus rule, touch panel, or another script:

```lua
-- Set Romy to 21.5 °C (stored as 215)
SetUserParam(0, "Romy_Setpoint", 215)
```

The `salus_set.lua` event script fires immediately, pushes the command to the gateway, and switches the device to **permanent hold** at that temperature.

To change mode without changing the setpoint, write to `_HoldType`:
```lua
SetUserParam(0, "Romy_HoldType", 0)   -- back to schedule
SetUserParam(0, "Romy_HoldType", 7)   -- off (frost protection)
SetUserParam(0, "Romy_HoldType", 10)  -- eco mode
```

---

## Hold type reference

| Value | Meaning |
|---|---|
| `0` | Follow heating schedule |
| `1` | Temporary hold |
| `2` | Permanent hold at setpoint |
| `7` | Off (frost protection ~5 °C) |
| `10` | Eco / setback |

---

## Compatibility

- **Gateway:** Salus / Unisenza Plus PUMG021GW
- **Radiators:** Unisenza Plus PUMM01102 panel radiators (and other `sTherS`-type Salus devices)
- **Controller:** C-Bus SpaceLogic 5500AC (LogicMachine OEM), any firmware
- **Lua:** 5.1 compatible; no external packages required

---

## Credits

Protocol reverse-engineered from live traffic captures of the Unisenza Plus iOS app.  AES key derivation confirmed against the [pyit600](https://github.com/jnimmo/pyit600) Home Assistant integration.
