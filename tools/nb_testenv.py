#!/usr/bin/env python3
"""Create, inspect and remove a NetBird test setup for netbird-lite via the REST API."""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

EPILOG = """\
commands:
  setup     create the group 'esp32-test', a reusable setup key 'esp32-nbl-test' (valid for
            7 days, 20 uses, puts new peers into the group) and two policies that allow
            ICMP and TCP port 80 from --source-group to the group. The setup key is written
            to .secrets/setup_key.txt (mode 0600) for use in sdkconfig.defaults*.local.
  status    list the peers in 'esp32-test', the two policies and the setup key
  teardown  delete the peers in 'esp32-test', the two policies, the setup key and the
            group; asks for confirmation unless --yes is given

The source group has no default on purpose: it decides which peers of your account may
reach the test devices. Pass the group of the machine that runs tools/e2e_test.sh, or
'All' (NetBird's built-in group of every peer) to allow all peers.

Before every change the current groups, policies and setup keys are saved to
.secrets/backup_<timestamp>.json (mode 0600). .secrets/ is gitignored.

One policy per protocol: NetBird (v0.80) assigns the policy's own ID to every rule of a
newly created policy, and the rule ID is the primary key, so a policy created with two
rules keeps only one of them.

example:
  export NETBIRD_URL=https://api.netbird.io
  read -rs NETBIRD_API_TOKEN && export NETBIRD_API_TOKEN   # paste the token (not echoed)
  tools/nb_testenv.py setup --source-group All
"""

GROUP = "esp32-test"
KEYNAME = "esp32-nbl-test"
POLICIES = {"icmp": "ESP32-Test (ICMP)", "tcp": "ESP32-Test (TCP 80)"}
SECRETS = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".secrets"))


class Api:
    def __init__(self, url, token):
        url = url.rstrip("/")
        if url.endswith("/api"):
            url = url[: -len("/api")]
        self.base = url + "/api"
        self.token = token

    def call(self, method, path, body=None):
        req = urllib.request.Request(
            self.base + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Authorization": "Token " + self.token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            sys.exit(f"error: {method} {path}: HTTP {e.code} {e.read().decode(errors='replace')[:300]}")
        except urllib.error.URLError as e:
            sys.exit(f"error: {method} {path}: {e.reason}")
        return json.loads(raw) if raw else {}

    def get(self, path):
        return self.call("GET", path)

    def by_name(self, path):
        return {x["name"]: x for x in self.get(path)}


def write_private(path, text):
    """Write a file that only the owner can read (created with mode 0600, no window)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd, "w") as f:
        f.write(text)


def backup(api):
    p = os.path.join(SECRETS, f"backup_{time.strftime('%Y%m%d_%H%M%S')}.json")
    data = {k: api.get(k) for k in ("/groups", "/policies", "/setup-keys")}
    write_private(p, json.dumps(data, indent=1))
    print("backup:", p)


def test_peers(api):
    return [p for p in api.get("/peers") if any(g.get("name") == GROUP for g in p.get("groups", []))]


def setup(api, src):
    groups = api.by_name("/groups")
    if src not in groups:
        sys.exit(f"error: source group '{src}' does not exist (use 'All' for every peer)")
    backup(api)
    if GROUP in groups:
        print(f"group '{GROUP}' exists, reusing it")
        gid = groups[GROUP]["id"]
    else:
        gid = api.call("POST", "/groups", {"name": GROUP})["id"]
        print(f"group '{GROUP}' created")
    key_file = os.path.join(SECRETS, "setup_key.txt")
    if any(k["name"] == KEYNAME and k["valid"] for k in api.get("/setup-keys")):
        if os.path.exists(key_file):
            print(f"a valid setup key '{KEYNAME}' exists, see {key_file}")
        else:
            print(f"a valid setup key '{KEYNAME}' exists, but {key_file} is missing; the API does"
                  " not return the key again - run teardown and setup to get a new one")
    else:
        k = api.call("POST", "/setup-keys", {"name": KEYNAME, "type": "reusable", "expires_in": 7 * 86400,
                                             "auto_groups": [gid], "usage_limit": 20, "ephemeral": False})
        write_private(key_file, k["key"])
        print(f"setup key '{KEYNAME}' created ->", key_file)
    pols = api.by_name("/policies")
    for proto, name in POLICIES.items():
        if name in pols:
            print(f"policy '{name}' exists")
            continue
        rule = {"name": name, "enabled": True, "action": "accept", "bidirectional": False,
                "protocol": proto, "sources": [groups[src]["id"]], "destinations": [gid]}
        if proto == "tcp":
            rule["ports"] = ["80"]
        api.call("POST", "/policies", {"name": name, "description": "netbird-lite test", "enabled": True,
                                       "rules": [rule]})
        stored = api.by_name("/policies")[name]["rules"]
        if len(stored) != 1 or stored[0].get("protocol") != proto:
            sys.exit(f"error: policy '{name}' was stored with unexpected rules: {stored}")
        print(f"policy '{name}' created")
    status(api)


def status(api):
    peers = test_peers(api)
    print(f"peers in '{GROUP}': {len(peers)}")
    for p in peers:
        print(" ", {k: p.get(k) for k in ("name", "ip", "connected", "last_seen", "version", "os")})
    pols = api.by_name("/policies")
    for name in POLICIES.values():
        print(f"policy '{name}':", "present" if name in pols else "missing")
    keys = [(k["name"], "valid" if k["valid"] else "invalid", f"used {k['used_times']}x")
            for k in api.get("/setup-keys") if k["name"] == KEYNAME]
    print("setup keys:", keys or "none")


def teardown(api, assume_yes):
    groups = api.by_name("/groups")
    peers = test_peers(api)
    pols = api.by_name("/policies")
    pol_names = [n for n in POLICIES.values() if n in pols]
    keys = [k for k in api.get("/setup-keys") if k["name"] == KEYNAME]
    if not (peers or pol_names or keys or GROUP in groups):
        print("nothing to delete")
        return
    print("to be deleted:")
    for p in peers:
        print(f"  peer    {p['name']} ({p.get('ip')})")
    for n in pol_names:
        print(f"  policy  {n}")
    for k in keys:
        print(f"  key     {k['name']}")
    if GROUP in groups:
        print(f"  group   {GROUP}")
    if not assume_yes:
        if not sys.stdin.isatty():
            sys.exit("error: not a terminal - pass --yes to confirm")
        if input("delete these objects? [y/N] ").strip().lower() not in ("y", "yes"):
            sys.exit("aborted")
    backup(api)
    for p in peers:
        api.call("DELETE", f"/peers/{p['id']}")
        print("peer deleted:", p["name"])
    for n in pol_names:
        api.call("DELETE", f"/policies/{pols[n]['id']}")
        print("policy deleted:", n)
    for k in keys:
        api.call("DELETE", f"/setup-keys/{k['id']}")
        print("setup key deleted:", k["name"])
    if GROUP in groups:
        api.call("DELETE", f"/groups/{groups[GROUP]['id']}")
        print("group deleted:", GROUP)
    key_file = os.path.join(SECRETS, "setup_key.txt")
    if os.path.exists(key_file):
        os.remove(key_file)


def main():
    ap = argparse.ArgumentParser(
        description="Create, inspect and remove a NetBird test setup for netbird-lite via the REST API.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--url", default=os.environ.get("NETBIRD_URL", ""),
                    help="NetBird management URL, e.g. https://api.netbird.io for NetBird Cloud or "
                         "https://netbird.example.com when self-hosted (default: $NETBIRD_URL)")
    ap.add_argument("--token", default=os.environ.get("NETBIRD_API_TOKEN", ""),
                    help="personal access token (default: $NETBIRD_API_TOKEN; prefer the variable, "
                         "a token on the command line ends up in shell history and process lists)")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="{setup,status,teardown}")
    p_setup = sub.add_parser("setup", help="create group, setup key and policies")
    p_setup.add_argument("--source-group", required=True,
                         help="group whose peers may reach the test devices ('All' for every peer)")
    sub.add_parser("status", help="show peers, policies and setup key of the test setup")
    p_down = sub.add_parser("teardown", help="delete peers, policies, setup key and group")
    p_down.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    a = ap.parse_args()
    if not a.url or not a.token:
        ap.error("set NETBIRD_URL and NETBIRD_API_TOKEN (or pass --url / --token)")
    api = Api(a.url, a.token)
    if a.cmd == "setup":
        setup(api, a.source_group)
    elif a.cmd == "status":
        status(api)
    else:
        teardown(api, a.yes)


if __name__ == "__main__":
    main()
