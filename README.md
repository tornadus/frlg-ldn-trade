# frlg-ldn-trade

A proof-of-concept demonstrating that it is indeed possible for a computer to interact with Gen 3 Pokémon games running on Switch/Switch 2 via local wireless (LDN).

---

## Why?

This project basically exists to prove that it can be done. From here, I'm hoping the community takes notice so that we can get things like an unofficial GTS and online battling going. It should serve as a pretty good reference for anyone interested in pursuing these goals or anything else related to multiplayer within these games. And before you ask, yes, **AI tools were used extensively during the creation of this project**. Difficult to call it "vibe coding" though, Claude required A LOT of steering and was basically lost without me laying out the path forward step-by-step. The main benefit was massively speeding up the reverse engineering work. If you'd like to contribute to the effort, join the Discord!
https://discord.gg/mVnpEywN

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
```sudo -E ./venv/bin/python frlgtrade.py --live -o output.pk3 PARTY1.pk3 PARTY2.pk3```

**Optional Flags (not comprehensive):**

| Flag         | Options          | Purpose        |
|--------------|------------------|----------------|
| --verbose    | N/A              | Verbose output  |
| --phy        | phy# (e.g. phy1)  | WiFi phy selection |
| --keys       | /path/to/prod.keys | non-default prod.keys location |

Above is the configuration I suggest using if you'd like a quick and easy demonstration of the program. You can use any of the listed optional flags, they're safe. Many of the undocumented ones are either unfinished, untested, internal tools, or artifacts of experiments that did not/have not yet panned out.

**Setup**
1. Create a Python venv and install all requirements in ``requirements.txt``
2. Ensure your WiFi card is unmanaged. The easiest way to accomplish this is stopping NetworkManager.
3. Ensure you can become root. The script requires root to run.

**Step-by-step Usage**
1. Select trading at the direct corner and make your console the "Leader".
2. Run the script. It may take multiple times to successfully connect.
3. Approve the join request from "EMU".
4. Walk to the LEFT CHAIR in the trading room. Walking may be laggy.
5. Select the Pokémon you'd like to trade away.
6. Accept the trade confirmation. You will be traded the *2nd* simulated party member.
7. Once you return to the trade menu, cancel the trade.
8. Walk out.
9. You'll find PARTY2.pk3 in your party, and the Pokémon you traded will be in pwd as output.pk3 (or whatever you called it). 
 
## Credits
- [kinnay](https://github.com/kinnay) - For the [LDN library](https://github.com/kinnay/LDN) this is built upon, and the excellent [NintendoClients Wiki](https://github.com/kinnay/NintendoClients/wiki)
- [pokefirered](https://github.com/pret/pokefirered) - A full decompilation of FireRed/LeafGreen, including the Switch port. It served as an important reference.

## License
AGPLv3
