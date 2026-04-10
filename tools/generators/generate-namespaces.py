#!/usr/bin/env python3
"""
Generate random `hkey namespace create` commands.

Examples:
  python gen_namespaces.py --count 25
  python gen_namespaces.py --count 25 --exec
  python gen_namespaces.py --count 100 --seed 42 --max-depth 4 --max-labels 5
"""

from __future__ import annotations

import argparse
import random
import re
import shlex
import subprocess
from typing import List

from faker import Faker

SAFE_KEY_RE = re.compile(r"[^a-z0-9_.-]+")


def safe_key(s: str) -> str:
    """
    Convert arbitrary text into a label-safe key fragment.
    Keeps: a-z 0-9 _ . -
    """
    s = s.strip().lower()
    s = s.replace(" ", "_")
    s = SAFE_KEY_RE.sub("", s)
    s = s.strip("._-")
    return s or "key"


def safe_value(s: str) -> str:
    """
    Values: keep it simple and CLI-friendly; avoid spaces and weird chars.
    """
    s = s.strip().lower()
    s = s.replace(" ", "-")
    s = SAFE_KEY_RE.sub("", s)
    s = s.strip("._-")
    return s or "value"


def random_segment(fake: Faker) -> str:
    # bias toward realistic "namespace-y" words
    base = random.choice(
        [
            fake.word(),
            fake.domain_word(),
            fake.color_name(),
            fake.job().split()[0],
            fake.city(),
        ]
    )
    seg = safe_key(base)
    # keep segments short-ish
    return seg[:20] if len(seg) > 20 else seg


def random_namespace(fake: Faker, min_depth: int, max_depth: int) -> str:
    depth = random.randint(min_depth, max_depth)
    segs = [random_segment(fake) for _ in range(depth)]
    return "/" + "/".join(segs)


def random_description(fake: Faker) -> str:
    # short and readable; you can swap to fake.sentence() if you want.
    return fake.sentence(nb_words=random.randint(3, 10)).rstrip(".")


def random_labels(fake: Faker, max_labels: int) -> List[str]:
    n = random.randint(0, max_labels)
    labels = []
    used_keys = set()

    for _ in range(n):
        k = safe_key(random.choice([fake.word(), fake.domain_word(), fake.color_name(), fake.job().split()[0]]))
        if k in used_keys:
            continue
        used_keys.add(k)

        v = safe_value(random.choice([fake.word(), fake.city(), fake.country(), fake.color_name()]))
        labels.append(f"{k}={v}")

    return labels


def build_cmd(namespace: str, description: str, labels: List[str]) -> List[str]:
    cmd = ["./target/debug/hkey", "namespace", "create", "--namespace", namespace, "--description", description]
    for lbl in labels:
        cmd += ["--label", lbl]
    return cmd


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10, help="How many namespaces to generate")
    ap.add_argument("--seed", type=int, default=None, help="Random seed for reproducible output")
    ap.add_argument("--min-depth", type=int, default=1, help="Min path segments (e.g. /foo)")
    ap.add_argument("--max-depth", type=int, default=4, help="Max path segments (e.g. /a/b/c/d)")
    ap.add_argument("--max-labels", type=int, default=4, help="Max labels per namespace (0..max)")
    ap.add_argument(
        "--exec",
        action="store_true",
        help="Actually run the command instead of printing it",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the command even when using --exec",
    )
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    fake = Faker()
    if args.seed is not None:
        Faker.seed(args.seed)

    for _ in range(args.count):
        ns = random_namespace(fake, args.min_depth, args.max_depth)
        desc = random_description(fake)
        labels = random_labels(fake, args.max_labels)
        cmd = build_cmd(ns, desc, labels)

        if args.dry_run or not args.exec:
            print(shlex.join(cmd))

        if args.exec:
            # Run and surface failures (non-zero exit)
            subprocess.run(cmd, check=False)


if __name__ == "__main__":
    main()
