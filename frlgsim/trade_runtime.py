"""Role-neutral runtime helpers shared by FRLG trade entry points."""

import os
import time

from . import mon as monmod


class ConsoleLog:
    """Two-level console logger used by both joiner and host applications."""

    def __init__(self, verbose, prefix="", *, start=None, output=print):
        self.verbose = bool(verbose)
        self.prefix = prefix
        self.start = time.monotonic() if start is None else start
        self.output = output

    def _ts(self):
        return f"[{time.monotonic() - self.start:7.1f}s]"

    def __call__(self, *parts):
        if self.verbose:
            if self.prefix:
                self.output(self._ts(), self.prefix, *parts)
            else:
                self.output(self._ts(), *parts)

    def info(self, *parts):
        if not self.verbose:
            self.output(self._ts(), *parts)


def parse_slots(spec, trades, party_len):
    """Parse a comma-separated list of distinct, zero-based party slots."""
    if not spec:
        return None
    try:
        slots = [int(value) for value in spec.split(",") if value != ""]
    except ValueError as exc:
        raise ValueError(f"--slots must be a comma list of integers, got {spec!r}") from exc
    if len(slots) != trades:
        raise ValueError(f"--slots must have {trades} entries (== --trades), got {len(slots)}")
    if len(set(slots)) != len(slots):
        raise ValueError(f"--slots must be distinct (a slot can't be offered twice): {slots}")
    if any(not 0 <= slot < party_len for slot in slots):
        raise ValueError(f"--slots must each be 0..{party_len - 1} (party size): {slots}")
    return slots


def load_party(paths, log=lambda *parts: None):
    """Load and describe a sequence of .pk3/.ek3 files."""
    party = [monmod.Mon.from_file(path) for path in paths]
    for index, pokemon in enumerate(party):
        log(f"  party slot {index}: {pokemon.describe()}")
    return party


def received_paths(mons, output_path, output_format, trades):
    """Return deterministic output paths for received Pokemon."""
    if trades == 1:
        return [output_path] if mons else []
    stem, _ = os.path.splitext(output_path)
    paths = []
    for index, pokemon in enumerate(mons, 1):
        species = "".join(char for char in pokemon.species_name if char.isalnum()) \
            or f"sp{pokemon.species}"
        paths.append(f"{stem}_trade{index}_{species}.{output_format}")
    return paths


def save_received_mons(mons, *, output_path, output_size, output_format, trades,
                       log=lambda *parts: None, output=print):
    """Persist received Pokemon and return the number written."""
    mons = list(mons)
    if not mons:
        return 0
    paths = received_paths(mons, output_path, output_format, trades)
    if trades == 1:
        pokemon, path = mons[0], paths[0]
        saver = pokemon.save_ek3 if output_format == "ek3" else pokemon.save_pk3
        saver(path, size=output_size)
        log(f"\nReceived: {pokemon.describe()}")
        getattr(log, "info", log)(f"Received: {pokemon.species_name} (#{pokemon.species})")
        output(f"Saved -> {path} ({output_format}, {output_size}B)")
        return 1

    log(f"\nReceived {len(mons)} mon(s) over {trades} trade(s):")
    getattr(log, "info", log)(f"Received {len(mons)} mon(s) over {trades} trade(s):")
    for index, (pokemon, path) in enumerate(zip(mons, paths), 1):
        saver = pokemon.save_ek3 if output_format == "ek3" else pokemon.save_pk3
        saver(path, size=output_size)
        log(f"  trade {index}: {pokemon.describe()}")
        getattr(log, "info", log)(f"  trade {index}: {pokemon.species_name} (#{pokemon.species})")
        output(f"    saved -> {path} ({output_format}, {output_size}B)")
    return len(mons)
