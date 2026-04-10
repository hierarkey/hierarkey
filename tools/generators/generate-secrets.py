#!/usr/bin/env python3
"""
Generate random secrets + multiple revisions, and activate a random revision (biased to latest).

Commands used (adjust if your CLI differs):
  - List namespaces:
      hkey namespace list --limit 10000 --json
      (fallback: hkey namespaces list --limit 10000 --json)
  - Create revision:
      hkey secret revision --ref <ref> --value <...>
      (optionally: --from-file <path> for large blobs)
  - Activate revision:
      hkey secret activate --ref <ref> --rev latest|<n>

Examples:
  python gen_secrets.py --count 25
  python gen_secrets.py --count 25 --exec
  python gen_secrets.py --count 50 --min-revs 1 --max-revs 6 --latest-weight 0.85 --exec --dry-run
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Any, List, Optional, Tuple

from faker import Faker

SAFE_SEG_RE = re.compile(r"[^a-z0-9_.-]+")


def safe_seg(s: str) -> str:
    s = s.strip().lower().replace(" ", "_")
    s = SAFE_SEG_RE.sub("", s)
    s = s.strip("._-")
    return s or "seg"


def run_json(cmd: List[str]) -> Any:
    p = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(p.stdout)


def fetch_namespaces(hkey_bin: str) -> List[str]:
    for argv in (
        [hkey_bin, "namespace", "list", "--limit", "10000", "--json"],
    ):
        try:
            data = run_json(argv)
            namespaces: List[str] = []

            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        namespaces.append(item)
                    elif isinstance(item, dict):
                        for k in ("namespace", "name", "path"):
                            if k in item and isinstance(item[k], str):
                                namespaces.append(item[k])
                                break
            elif isinstance(data, dict):
                items = data.get("entries")
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            ns = item.get("namespace") or item.get("name") or item.get("path")
                            if isinstance(ns, str):
                                namespaces.append(ns)

            namespaces = [ns for ns in namespaces if ns.startswith("/")]
            return sorted(set(namespaces))
        except subprocess.CalledProcessError:
            continue

    return []


def random_secret_path(fake: Faker) -> str:
    depth = random.randint(1, 3)
    parts = []
    for _ in range(depth):
        base = random.choice(
            [
                fake.word(),
                fake.domain_word(),
                fake.color_name(),
                fake.job().split()[0],
                fake.city(),
            ]
        )
        parts.append(safe_seg(base)[:20])
    # add a small suffix to reduce collisions
    parts[-1] = f"{parts[-1]}-{random.randint(1000, 9999)}"
    return "/".join(parts)


def make_ref(namespace: str, secret_path: str) -> str:
    return f"{namespace}:{secret_path}"


def gen_small_value(size_bytes: int) -> str:
    raw = os.urandom(size_bytes)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def gen_json_value(fake: Faker) -> str:
    payload = {
        "service": safe_seg(fake.domain_word()),
        "env": random.choice(["dev", "test", "prod"]),
        "token": gen_small_value(24),
        "issued_at": fake.iso8601(),
    }
    return json.dumps(payload, separators=(",", ":"))


def gen_pemish_value(approx_kib: int) -> str:
    body = base64.b64encode(os.urandom(approx_kib * 1024)).decode("ascii")
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return (
        "-----BEGIN CERTIFICATE-----\n"
        f"{wrapped}\n"
        "-----END CERTIFICATE-----\n"
    )


def choose_value(fake: Faker, max_size_kib: int, pem_ratio: float, json_ratio: float) -> Tuple[str, str]:
    r = random.random()
    if r < json_ratio:
        return ("json", gen_json_value(fake))
    if r < json_ratio + pem_ratio:
        kib = random.randint(max(1, max_size_kib // 4), max_size_kib)
        return ("pem", gen_pemish_value(kib))
    # small key-like
    return ("small", gen_small_value(random.choice([16, 24, 32, 48, 64])))


def random_labels(fake: Faker, max_labels: int) -> List[str]:
    n = random.randint(0, max_labels)
    labels: List[str] = []
    used = set()

    for _ in range(n):
        k = safe_seg(random.choice([fake.word(), fake.domain_word(), fake.color_name(), fake.job().split()[0]]))
        if k in used:
            continue
        used.add(k)
        v = safe_seg(random.choice([fake.word(), fake.city(), fake.country(), fake.color_name()]))
        labels.append(f"{k}={v}")

    return labels


def build_revision_cmd(
    hkey_bin: str,
    ref: str,
    value: str,
    note: Optional[str],
    use_file: bool,
) -> Tuple[List[str], Optional[str]]:
    """
    hkey secret revise --ref <ref> --value <...>
    (or --from-file for larger values)
    """
    tmp_path = None
    cmd = [hkey_bin, "secret", "revise", "--ref", ref]

    if note:
        cmd += ["--note", note]

    if use_file:
        fd, tmp_path = tempfile.mkstemp(prefix="hkey_secret_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(value)
        cmd += ["--from-file", tmp_path]
    else:
        cmd += ["--value", value]

    return cmd, tmp_path


def build_create_cmd(
    hkey_bin: str,
    ref: str,
    value: str,
    description: Optional[str],
    labels: List[str],
    use_file: bool,
) -> Tuple[List[str], Optional[str]]:
    """
    hkey secret create --ref <ref> --value <...>
    (or --from-file for larger values)
    """
    tmp_path = None
    cmd = [hkey_bin, "secret", "create", "--ref", ref]

    if description:
        cmd += ["--description", description]

    if use_file:
        fd, tmp_path = tempfile.mkstemp(prefix="hkey_secret_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(value)
        cmd += ["--from-file", tmp_path]
    else:
        cmd += ["--value", value]

    return cmd, tmp_path


def build_activate_cmd(hkey_bin: str, ref: str, rev: str) -> List[str]:
    return [hkey_bin, "secret", "activate", "--ref", f"{ref}@{rev}"]


def pick_activation_rev(n_revs: int, latest_weight: float) -> str:
    if n_revs <= 1:
        return "latest"
    if random.random() < latest_weight:
        return "latest"
    return str(random.randint(1, n_revs - 1))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10, help="How many *secrets* to generate")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--hkey", default="./target/debug/hkey", help="Path to hkey binary")
    ap.add_argument("--max-labels", type=int, default=4)

    ap.add_argument("--min-revs", type=int, default=1, help="Min revisions per secret")
    ap.add_argument("--max-revs", type=int, default=5, help="Max revisions per secret")
    ap.add_argument("--latest-weight", type=float, default=0.8, help="Chance to activate 'latest'")

    ap.add_argument("--max-size-kib", type=int, default=16, help="Max size for pem-ish blobs")
    ap.add_argument("--pem-ratio", type=float, default=0.25, help="Chance value is PEM-ish")
    ap.add_argument("--json-ratio", type=float, default=0.15, help="Chance value is JSON")

    ap.add_argument("--use-file-threshold", type=int, default=2048, help="If value > N bytes, use --from-file")
    ap.add_argument("--exec", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="Print commands even when using --exec")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        Faker.seed(args.seed)

    fake = Faker()

    namespaces = fetch_namespaces(args.hkey)
    if not namespaces:
        print("No namespaces found. Create namespaces first.", file=sys.stderr)
        sys.exit(2)

    temp_files: List[str] = []

    try:
        for _ in range(args.count):
            ns = random.choice(namespaces)
            secret_path = random_secret_path(fake)
            ref = make_ref(ns, secret_path)

            n_revs = random.randint(args.min_revs, args.max_revs)

            # Create initial secret
            base_desc = fake.sentence(nb_words=random.randint(3, 10)).rstrip(".")
            base_labels = random_labels(fake, args.max_labels)

            kind, value = choose_value(fake, args.max_size_kib, args.pem_ratio, args.json_ratio)
            use_file = len(value.encode("utf-8")) > args.use_file_threshold
            cmd, tmp = build_create_cmd(
                args.hkey,
                ref,
                value,
                base_desc,
                base_labels,
                use_file,
            )
            if tmp:
                temp_files.append(tmp)

            if args.dry_run or not args.exec:
                print(shlex.join(cmd))
            if args.exec:
                subprocess.run(cmd, check=False)

            # Create N revisions
            for i in range(0, n_revs + 1):
                note = fake.sentence(nb_words=random.randint(3, 10)).rstrip(".")

                kind, value = choose_value(fake, args.max_size_kib, args.pem_ratio, args.json_ratio)
                use_file = len(value.encode("utf-8")) > args.use_file_threshold
                cmd, tmp = build_revision_cmd(
                    args.hkey,
                    ref,
                    value,
                    note,
                    use_file,
                )
                if tmp:
                    temp_files.append(tmp)

                if args.dry_run or not args.exec:
                    print(shlex.join(cmd))
                if args.exec:
                    subprocess.run(cmd, check=False)

            # Activate a revision (biased to latest)
            act_rev = pick_activation_rev(n_revs, args.latest_weight)
            act_cmd = build_activate_cmd(args.hkey, ref, act_rev)

            if args.dry_run or not args.exec:
                print(shlex.join(act_cmd))
            if args.exec:
                subprocess.run(act_cmd, check=False)

    finally:
        for p in temp_files:
            try:
                os.remove(p)
            except OSError:
                pass


if __name__ == "__main__":
    main()
