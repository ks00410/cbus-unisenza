# cbus-unisenza

C-Bus / LogicMachine Lua scripts for controlling **Unisenza Plus** smart radiators from a Schneider Electric C-Bus SpaceLogic **5500AC** controller.

Communicates directly with the local Unisenza Plus gateway over your LAN — **no cloud, no internet required**.

> **Note:** The Unisenza Plus system is an OEM of the [Salus iT600](https://salus-controls.com) platform. The gateway API, protocol, and encryption are identical across both brands.

---

## How it works

The Unisenza Plus gateway exposes a local HTTP API on port 80. All requests and responses are **AES-256-CBC encrypted JSON**, with the key derived from the gateway's EUID (printed on the sticker). These scripts implement that protocol entirely in pure Lua — no external libraries or packages needed.

Radiators are **auto-discovered** from the gateway on every poll — there is no static device list to configure. The first poll logs a discovery summary showing every device found.

```
5500AC (LogicMachine) controller
  └── unisenza_poll.lua  (resident, every 30 s)
        └── unisenza.lua → POST /deviceid/read → gateway
              └── aes.lua  (pure-Lua AES-256-CBC + MD5)

  └── unisenza_set.lua  (event, on _Setpoint / _HoldType param change)
        └── unisenza.lua → POST /deviceid/write → gateway
```

---

## Files

| File | Type | Purpose |
|---|---|---|
| [`aes.lua`](aes.lua) | Lua library | Pure-Lua AES-256-CBC + MD5. Uses `bit` library on LogicMachine for speed. |
| [`unisenza.lua`](unisenza.lua) | Lua library | Gateway API: `read_all()`, `set_temperature()`, `set_hold()`, `Resident_Poll()` |
| [`script_resident_poll.lua`](script_resident_poll.lua) | Resident script | Thin caller — set Sleep = 30 s, paste as body. One `Resident_Poll(config)` call. |
| [`unisenza_set.lua`](unisenza_set.lua) | Event script | Fires when a `_Setpoint` or `_HoldType` param changes; pushes new value to gateway |

---

## Installation

### 1. Find your gateway EUID

The EUID is on the sticker on the **Unisenza Plus gateway** (model PUMG021GW). It looks like `001E5E090292DD94`.

### 2. Configure `unisenza.lua`

Edit the two lines at the top of [`unisenza.lua`](unisenza.lua):

```lua
M.GATEWAY_IP   = "192.168.1.59"      -- IP of your gateway (check your router)
M.GATEWAY_EUID = "001E5E090292DD94"  -- EUID from gateway sticker
```

That's the **only configuration required**. No device names to list.

### 3. Upload libraries to the 5500AC

In the LogicMachine web UI (**Scripting → Lua libraries**), upload:
- `aes.lua`
- `unisenza.lua`

### 4. Create the resident poll script

- **Scripting → Resident scripts → Add new**
- Name: `Unisenza Poll`
- Sleep time: `30` seconds
- Paste `script_resident_poll.lua` as the body
- Enable the script

On first run, enable `Debug = 1` and check the log. You will see:

```
UNISENZA_POLL: discovered 3 device(s) on gateway 192.168.1.59
UNISENZA_POLL:   Finn             uid=001e5e09029a8d34  model=100
UNISENZA_POLL:   Garage           uid=001e5e0902ab5302  model=100
UNISENZA_POLL:   Romy             uid=001e5e09029a8dbb  model=100
```

### 5. Create C-Bus User Parameters

Create these on network `0` (or whichever network you set in `CBUS_NETWORK`):

**Global:**
| Parameter | Type | Purpose |
|---|---|---|
| `Debug` | Number | `1` = verbose logging, `0` = silent |
| `Unisenza_Status` | String | Last poll result (`OK` or error) |
| `Unisenza_LastUpdated` | String | Timestamp of last successful poll |
| `Unisenza_DeviceCount` | Number | Count of discovered devices |

**Per device** (use the exact name from the discovery log, e.g. `Romy`):
| Parameter | Type | Notes |
|---|---|---|
| `NAME_CurrentTemp` | Number | Room temp ×10 (142 = 14.2 °C) |
| `NAME_Setpoint` | Number | Setpoint ×10 — **write this to control temperature** |
| `NAME_HoldType` | Number | 0=Schedule, 2=Hold, 7=Off, 10=Eco |
| `NAME_Demand` | Number | Heating demand 0–100 % |
| `NAME_Online` | Number | 1=online, 0=offline |

> **Why ×10?** C-Bus user parameters are integers. Multiplying by 10 means 21.5 °C is stored as `215`. Divide by 10 in any display rule or visualisation.

### 6. Create event scripts (one per radiator)

For each radiator (e.g. "Romy"):
- **Scripting → Event scripts → Add new**
- Name: `Unisenza Set Romy`
- Trigger: **User Parameter changed** → `Romy_Setpoint`
- Set `local RADIATOR_NAME = "Romy"` at the top
- Paste `unisenza_set.lua` as the body
- Enable the script

---

## Controlling a radiator

From a rule, touch panel, or another script:

```lua
-- Set Romy to 21.5 °C (switches to permanent hold automatically)
SetUserParam(0, "Romy_Setpoint", 215)

-- Change mode without touching the setpoint
SetUserParam(0, "Romy_HoldType", 0)   -- follow schedule
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
| `10` | Eco / setback mode |

---

## Compatibility

- **Gateway:** Unisenza Plus PUMG021GW (Salus iT600 OEM)
- **Radiators:** Unisenza Plus PUMM01102 panel radiators and other `sTherS`-type devices
- **Controller:** C-Bus SpaceLogic 5500AC (LogicMachine OEM), any firmware
- **Lua:** 5.1 compatible; no external packages or libraries required

---

## Credits

Protocol reverse-engineered from live traffic captures of the Unisenza Plus iOS app. AES key derivation confirmed against the [pyit600](https://github.com/jnimmo/pyit600) Home Assistant integration.
