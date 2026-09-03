# frlg-ldn-trade

A proof-of-concept demonstrating that it is indeed possible for a computer to interact with Gen 3 Pokémon games running on Switch/Switch 2 via local wireless (LDN).

---

## Why?

This project basically exists to prove that it can be done. From here, I'm hoping the community takes notice so that we can get things like an unofficial GTS and online battling going. It should serve as a pretty good reference for anyone interested in pursuing these goals or anything else related to multiplayer within these games. And before you ask, yes, **AI tools were used extensively during the creation of this project**. Difficult to call it "vibe coding" though, Claude required A LOT of steering and was basically lost without me laying out the path forward step-by-step. The main benefit was massively speeding up the reverse engineering work. If you'd like to contribute to the effort, join the [Discord!](https://discord.gg/PyvaVYnpXC)

## Demonstration
https://github.com/user-attachments/assets/b0df878e-67f0-483d-ae81-583cfc2a8692

This demo was recorded using the **ALFA AWUS036ACHM**. The RZ616 is half as fast on average and sometimes deadlocks before gracefully exiting.

## Features

- End-to-end trading with a real game running on a real Switch
- .pk3/.ek3 input and output

## Requirements
- Linux
- Python 3.12+, and a venv with requirements installed (see requirements.txt)
- a compatible WiFi card (see below)
- A Switch or Switch 2 with FRLG, played to the point where the Direct Corner has been unlocked (~20-40 minutes)
- At least 2 .pk3 files to serve as simulated party members/trade fodder
- Switch prod.keys (the default location is ``~/.switch/prod.keys``)

### Tested WiFi Cards

| Model            | Type           | Driver  | Reliability  |
|------------------|----------------|---------|---------------
| AMD RZ616        | Internal (M.2) | mt7921e | Low          |
| ALFA AWUS036ACHM | External       | mt76x0u | High         |
| Realtek RTL8821CE | Internal (PCIe 1x) | rtw88_8821ce | High |

### Known Problematic WiFi Cards

| Model            | Type           | Driver  | Issue        |
|------------------|----------------|---------|---------------
| Intel AX200        | Internal (M.2) | iwlwifi | Unable to be assigned ip |
| Atheros AR9271 | External       | ath9k_htc | Unable to be assigned ip (most of the time) |

## Usage

### Join a Switch-hosted trade

Use the original joiner when the Switch is the Direct Corner leader:

```bash
sudo -E ./.venv/bin/python frlgtrade.py --live -o output.pk3 PARTY1.pk3 PARTY2.pk3
```

### Host a Direct Corner trade

Start a Direct Corner host with:

```bash
sudo -E ./.venv/bin/python frlgtrade_host.py --live -o output.pk3 PARTY1.pk3 PARTY2.pk3
```

Linux advertises the group and acts as the trade leader. With the default settings it offers the
second supplied party member (`PARTY2.pk3`) and writes the Pokémon received from the Switch to
`output.pk3`. Run `frlgtrade_host.py --help` for the complete operational CLI.

**Optional Flags (not comprehensive):**

| Flag         | Options          | Purpose        |
|--------------|------------------|----------------|
| `--verbose` | N/A | Verbose protocol output |
| `--phy` | phy name (for example `phy1`) | Wi-Fi PHY selection |
| `--keys` | `/path/to/prod.keys` | Non-default prod.keys location |
| `--slot` | zero-based party index | Host party member offered in the trade |
| `--capture` | output path | Optional JSONL diagnostic capture |
| `--ot` | Gen III trainer name | Override `DEFAULT_TRAINER.name` for this run |
| `--version` | `firered` or `leafgreen` | Override the configured game version |
| `--id` | decimal `TID[:SID]` | Override the trainer ID, and optionally secret ID |

The command above is the recommended demonstration configuration. The help output is the authoritative
list of supported options for each entry point.

**Setup**
1. Create a Python venv and install all requirements in ``requirements.txt``
2. Keep NetworkManager away from the LDN interfaces. Marking your WiFi card unmanaged is **not enough**: the join creates a fresh `ldnclient` interface mid-run, NetworkManager grabs it and points wpa_supplicant at it, and the join then fails with `[Errno 114] Match already configured`. Install a config that excludes the LDN interfaces by name:

   ```
   # /etc/NetworkManager/conf.d/zz-ldn-unmanaged.conf
   [keyfile]
   unmanaged-devices=interface-name:ldnclient;interface-name:ldn;interface-name:ldn-mon;interface-name:ldn-tap
   ```

   then `sudo systemctl restart NetworkManager`. Name the file `zz-*` so it sorts last: some distros (e.g. Linux Mint's `ubuntu-system-adjustments.conf`) ship a later-sorting file that sets `unmanaged-devices=none` and silently overrides yours. Verify with `NetworkManager --print-config | grep unmanaged` — it must show the `interface-name:ldn...` list. (Stopping NetworkManager entirely also works, but the config file is a one-time setup that survives reboots.)
3. Ensure you can become root. The script requires root to run.

### Trainer identity

Both entry points start from `DEFAULT_TRAINER` in
[`frlgsim/config.py`](frlgsim/config.py). Use `--ot`, `--version`, and `--id` for per-run overrides.
The ID format is decimal `TID[:SID]`:

```bash
# Set TID to 12345 and retain DEFAULT_TRAINER.sid
./.venv/bin/python frlgtrade.py --live --id=12345 PARTY1.pk3 PARTY2.pk3

# Set TID to 12345 and SID to 34567 while hosting
sudo -E ./.venv/bin/python frlgtrade_host.py --live --id=12345:34567 PARTY1.pk3 PARTY2.pk3
```

Each component must be between 0 and 65535. The resulting 32-bit LinkPlayer ID is encoded as
`(SID << 16) | TID`. The resolved profile is used consistently by discovery, Pia Session, RFU game
data, LinkPlayer, and trainer-card identity. Edit `DEFAULT_TRAINER` for gender, language, National
Dex, or game-completion defaults that do not have CLI flags.

### Hosting diagnostics

- `ldn_scan.py` prints discoverable LDN networks and decoded FRLG application data.
- `sniff.py` captures advertisement and management traffic from a monitor-capable radio.
- `ldn_debug_report.sh` records local radio, interface, route, and NetworkManager state for debugging.
- `frlgtrade_host.py --capture FILE` writes the host protocol trace as JSONL.

See [the host design document](docs/frlgtrade_host_design.md) for the component boundaries, protocol
flow, timing ownership, trainer propagation, and shutdown sequence.

**Step-by-step Usage**

1. Run the host command and wait for `Hosting Direct Corner`.
2. On the Switch, enter the Direct Corner and choose **Join Group**.
3. Select the Linux trainer (`EMU` by default) and join. The Linux leader performs its room-entry
   route automatically; wait until the host reports that trade selection is active.
4. On the Switch, select the Pokémon to trade away and accept the confirmation. With the example
   command, the Switch receives `PARTY2.pk3`.
5. After the trade and save sequence returns to the trade menu, wait for the host prompt, then select
   **CANCEL** and confirm **YES**.
6. Allow the automated room exit and disconnect to finish. The received Pokémon is saved as
   `output.pk3` (or the path passed to `--out`).
 
## Credits
- [kinnay](https://github.com/kinnay) - For the [LDN library](https://github.com/kinnay/LDN) this is built upon, and the excellent [NintendoClients Wiki](https://github.com/kinnay/NintendoClients/wiki)
- [pokefirered](https://github.com/pret/pokefirered) - A full decompilation of FireRed/LeafGreen, including the Switch port. It served as an important reference.

## License
AGPLv3
