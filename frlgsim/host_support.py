"""Small OS-facing helpers shared by host tools."""

import os


def resolve_keys(path):
    """Resolve prod.keys correctly when the program is launched through sudo."""
    expanded = os.path.expanduser(path)
    if os.path.exists(expanded):
        return expanded
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and path.startswith("~"):
        try:
            import pwd
            home = pwd.getpwnam(sudo_user).pw_dir
            candidate = (os.path.join(home, path[2:]) if path.startswith("~/")
                         else path.replace("~", home, 1))
            if os.path.exists(candidate):
                return candidate
        except (KeyError, ImportError):
            pass
    return expanded
