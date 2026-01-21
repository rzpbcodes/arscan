
import re
from packaging.version import Version, InvalidVersion

"""
is_safe_pragma("pragma solidity ^0.7.0", "0.8.0")
is_safe_pragma("pragma solidity 0.8.7", "0.8.0")
is_safe_pragma("pragma solidity ^0.8.0", "0.8.0")
is_safe_pragma("pragma solidity >=0.6.0 <0.8.0", "0.8.0")
is_safe_pragma("pragma solidity >=0.7.0", "0.8.0")
is_safe_pragma("pragma solidity <0.6.5", "0.8.0")
is_safe_pragma("pragma solidity >=0.6.0 <0.7.0", "0.8.0")
is_safe_pragma("pragma solidity 0.7.4", "0.8.0")
"""

def is_safe_pragma(pragma_str: str, target: str) -> bool:
    """
    Returns False (vulnerable) if the pragma allows any compiler < target,
    True (safe) if it restricts all allowed versions >= target.
    """
    m = re.search(r"pragma\s+solidity\s*(.+?)?$", pragma_str.strip())
    if not m:
        raise ValueError(f"Not a solidity pragma: {pragma_str!r}")
    constraint = m.group(1)
    target_v = Version(target)

    for clause in constraint.split("||"):
        clause = clause.strip()
        # find (op, version) pairs
        tokens = re.findall(r"(>=|<=|\^|>|<)?\s*([0-9]+(?:\.[0-9]+){1,2})", clause)

        mins = []
        for op, ver_str in tokens:
            try:
                v = Version(ver_str)
            except InvalidVersion:
                continue

            if op in (">=", "^", ""):    # now treat "" (bare version) as exact
                mins.append(v)
            elif op == ">":
                # bump patch
                parts = list(v.release)
                parts[-1] += 1
                mins.append(Version(".".join(map(str, parts))))
            # '<', '<=', no lower-bound

        # if no lower-bound seen, clause allows from 0.0.0
        min_v = min(mins) if mins else Version("0.0.0")

        if min_v < target_v:
            return False

    return True




