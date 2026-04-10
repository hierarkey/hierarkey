#!/usr/bin/env python3
"""
Generate random `hkey create-*` account commands.

Examples:
  python gen_accounts.py --count 25
  python gen_accounts.py --count 25 --exec
  python gen_accounts.py --count 100 --seed 42 --max-labels 5
"""

from __future__ import annotations

import argparse
import random
import re
import shlex
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from faker import Faker

SAFE_KEY_RE = re.compile(r"[^a-z0-9_.-]+")
SAFE_USER_RE = re.compile(r"[^a-z0-9_.-]+")


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


def safe_username(s: str) -> str:
    """
    Usernames: keep it CLI- and URL-friendly.
    """
    s = s.strip().lower()
    s = s.replace(" ", ".")
    s = SAFE_USER_RE.sub("", s)
    s = s.strip("._-")
    # avoid empty and overly long
    if not s:
        s = "user"
    return s[:32]


def random_description(fake: Faker) -> str:
    return fake.sentence(nb_words=random.randint(3, 10)).rstrip(".")


def random_labels(fake: Faker, max_labels: int) -> List[str]:
    n = random.randint(0, max_labels)
    labels: List[str] = []
    used_keys = set()

    for _ in range(n):
        k = safe_key(
            random.choice(
                [
                    fake.word(),
                    fake.domain_word(),
                    fake.color_name(),
                    fake.job().split()[0],
                ]
            )
        )
        if not k or k in used_keys:
            continue
        used_keys.add(k)

        v = safe_value(random.choice([fake.word(), fake.city(), fake.country(), fake.color_name()]))
        labels.append(f"{k}={v}")

    return labels


def random_username(fake: Faker) -> str:
    # Make it fairly realistic and unique-ish
    base = random.choice(
        [
            fake.user_name(),
            f"{fake.first_name()}_{fake.last_name()}",
            f"{fake.first_name()}{random.randint(1, 9999)}",
        ]
    )
    return safe_username(base)


def random_full_name(fake: Faker) -> str:
    return fake.name()


def random_email(fake: Faker, username: str) -> str:
    # keep stable-ish and simple
    domain = random.choice([fake.free_email_domain(), fake.domain_name(), "example.com"])
    local = safe_username(username).replace(".", "_")
    return f"{local}@{domain}"


@dataclass
class AccountSpec:
    kind: str  # "user" | "admin" | "service"
    username: str
    email: Optional[str]
    full_name: Optional[str]
    activate: Optional[bool]
    description: str
    labels: List[str]


def choose_kind() -> str:
    # 10% admin, 30% user, 60% service
    r = random.random()
    if r < 0.10:
        return "admin"
    if r < 0.40:
        return "user"
    return "service"


def build_spec(fake: Faker, kind: str, max_labels: int) -> AccountSpec:
    username = random_username(fake)
    description = random_description(fake)
    labels = random_labels(fake, max_labels)

    if kind in ("user", "admin"):
        full_name = random_full_name(fake)
        email = random_email(fake, username)
    else:
        full_name = None
        email = None

    activate: Optional[bool]
    if kind in ("user", "service"):
        # randomize activate
        activate = random.choice([True, False])
    else:
        activate = None

    return AccountSpec(
        kind=kind,
        username=username,
        email=email,
        full_name=full_name,
        activate=activate,
        description=description,
        labels=labels,
    )


def build_cmd(spec: AccountSpec) -> List[str]:
    # Adjust binary path if needed
    base = ["./target/debug/hkey", "account"]

    if spec.kind == "user" or spec.kind == "admin":
        cmd = base + [
            "create-user",
            "--name",
            spec.username,
            "--email",
            spec.email or "",
            "--full-name",
            spec.full_name or "",
            "--description",
            spec.description,
            "--insecure-password",
            f"password{spec.username}"
        ]
        if spec.activate:
            cmd.append("--activate")

    elif spec.kind == "service":
        cmd = base + [
            "create-service",
            "--name",
            spec.username,
            "--description",
            spec.description,
        ]
        if spec.activate:
            cmd.append("--activate")

    else:
        raise ValueError(f"Unknown kind: {spec.kind}")

    for lbl in spec.labels:
        cmd += ["--label", lbl]

    return cmd


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10, help="How many accounts to generate")
    ap.add_argument("--seed", type=int, default=None, help="Random seed for reproducible output")
    ap.add_argument("--max-labels", type=int, default=4, help="Max labels per account (0..max)")
    ap.add_argument("--exec", action="store_true", help="Actually run the command instead of printing it")
    ap.add_argument("--dry-run", action="store_true", help="Print the command even when using --exec")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    fake = Faker()
    if args.seed is not None:
        Faker.seed(args.seed)

    # avoid duplicates in a single run
    seen_usernames = set()

    for _ in range(args.count):
        kind = choose_kind()

        # Ensure unique usernames within this run
        spec = build_spec(fake, kind, args.max_labels)
        tries = 0
        while spec.username in seen_usernames and tries < 20:
            spec = build_spec(fake, kind, args.max_labels)
            tries += 1
        seen_usernames.add(spec.username)

        cmd = build_cmd(spec)

        if args.dry_run or not args.exec:
            print(shlex.join(cmd))

        if args.exec:
            subprocess.run(cmd, check=False)


if __name__ == "__main__":
    main()
