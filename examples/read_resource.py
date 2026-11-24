"""A normal Python HTTPS client. Proxy and CA configuration come from the trusted launcher."""

import json
import os
import urllib.request


def main():
    request = urllib.request.Request(
        os.environ["KEYHERON_URL"], headers={"Accept": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        content = response.read()
        print(json.dumps({"status": response.status, "bytes": len(content)}))


if __name__ == "__main__":
    main()
