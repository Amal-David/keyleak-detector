"""Private bounded snapshot helper. Only the parent consumes stdout bytes.

Invoked as a trusted installed script, never with user-supplied executable code.
No logging, network libraries, environment configuration, or arbitrary paths.
"""

import json
import os
import stat
import sys

LIMIT = 128 * 1024


def main() -> int:
    """Read one granted file relative to a pre-opened root and emit bounded bytes."""
    parent = None
    descriptor = None
    try:
        root_fd = int(sys.argv[1])
        parts = json.loads(sys.stdin.buffer.read(8193))
        if not isinstance(parts, list) or not 1 <= len(parts) <= 32:
            return 2
        if any(type(p) is not str or p in ("", ".", "..") or any(c in p for c in ("/", "\\", "\x00")) for p in parts):
            return 2
        parent = os.dup(root_fd)
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return 2
        if info.st_size > LIMIT:
            return 3
        chunks, remaining = [], LIMIT + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 16 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > LIMIT:
            return 3
        after = os.fstat(descriptor)
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            return 2
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 2
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


if __name__ == "__main__":
    raise SystemExit(main())
