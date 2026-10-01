#!/usr/bin/env python3
"""Regenerates the static Lupetto mockup pages in design/mockup/.

Viewing the mockup needs no build step: the generated HTML is committed.
This script only exists so the sample data and repeated markup stay consistent:

    python3 design/mockup/_src/generate.py

All data below is SAMPLE data. Package names/versions come from the real signed
Wolfi index and advisory IDs from the real Wolfi security feed (2026-10-01);
severities, digests, dates, and build history are invented for illustration.
"""

import hashlib
import html
import json
import pathlib

OUT = pathlib.Path(__file__).resolve().parent.parent
E = html.escape

REG_HOST = "registry.example.com"
REG_REPO = "team/lupetto"
INDEX_SHA = "bad5600da4ee8c2d8ebba2e687fa3555192abe3231f407d3cb6266e30b3af860"
FEED_SHA = "163ee313794e6780cfdca8e64c76d80494e315155cd6d72cb361cedf1857a3f2"


def dg(seed):
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def short(d):
    return d[:19]  # sha256:0123456789ab


# --------------------------------------------------------------------------- icons

ICONS = {
    "images": '<path class="duo" d="M12 3 3 7.5l9 4.5 9-4.5z"/><path d="M12 3 3 7.5l9 4.5 9-4.5z"/><path d="m3 12 9 4.5 9-4.5"/><path d="m3 16.5 9 4.5 9-4.5"/>',
    "catalog": '<rect class="duo" x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>',
    "builds": '<path class="duo" d="M4 15h16v5H4z"/><path d="M4 15h16v5H4z"/><path d="M7 15V9h10v6"/><path d="M9.5 9V4h5v5"/>',
    "search": '<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "check": '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    "ok": '<circle class="duo" cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="9"/><path d="m8 12.3 2.8 2.8L16.3 9.5"/>',
    "update": '<circle class="duo" cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="9"/><path d="M12 16.5v-9M8 11l4-4 4 4"/>',
    "rebuild": '<path d="M19.5 11A7.5 7.5 0 0 0 6 6.6L4.5 8"/><path d="M4.5 4v4h4"/><path d="M4.5 13A7.5 7.5 0 0 0 18 17.4l1.5-1.4"/><path d="M19.5 20v-4h-4"/>',
    "notbuilt": '<circle cx="12" cy="12" r="8.5" stroke-dasharray="3.2 3"/><path d="M12 8.5v7M8.5 12h7"/>',
    "error": '<path class="duo" d="M12 3.5 2.5 20h19z"/><path d="M12 3.5 2.5 20h19z"/><path d="M12 10v4.5M12 17.3v.2"/>',
    "fail": '<circle class="duo" cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>',
    "local": '<path class="duo" d="M4.5 5h15v10.5h-15z"/><path d="M4.5 5h15v10.5h-15z"/><path d="M2 19h20"/>',
    "registry": '<rect class="duo" x="3.5" y="4" width="17" height="7" rx="1.5"/><rect x="3.5" y="4" width="17" height="7" rx="1.5"/><rect x="3.5" y="13" width="17" height="7" rx="1.5"/><path d="M7.5 7.5h.01M7.5 16.5h.01"/>',
    "record": '<path class="duo" d="M6 3h8l4 4v14H6z"/><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
    "clock": '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    "info": '<circle class="duo" cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8v.2"/>',
    "shield": '<path class="duo" d="M12 3 4.5 6v5.5c0 4.5 3.2 8 7.5 9.5 4.3-1.5 7.5-5 7.5-9.5V6z"/><path d="M12 3 4.5 6v5.5c0 4.5 3.2 8 7.5 9.5 4.3-1.5 7.5-5 7.5-9.5V6z"/>',
    "download": '<path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14"/>',
    "compare": '<path d="M5 8h13M14.5 4.5 18 8l-3.5 3.5M19 16H6M9.5 12.5 6 16l3.5 3.5"/>',
    "chev": '<path d="m9.5 6 6 6-6 6"/>',
    "close": '<path d="m6.5 6.5 11 11M17.5 6.5l-11 11"/>',
    "lock": '<rect class="duo" x="5" y="10.5" width="14" height="10" rx="1.5"/><rect x="5" y="10.5" width="14" height="10" rx="1.5"/><path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3"/>',
    "running": '<circle cx="12" cy="12" r="8.5" stroke-dasharray="38 16"/><path d="M12 8v4l2.5 1.5"/>',
    "skip": '<circle cx="12" cy="12" r="8.5"/><path d="M8.5 12h7"/>',
    "pending": '<circle cx="12" cy="12" r="8.5" stroke-dasharray="2 3.4"/>',
    "package": '<path class="duo" d="M3.5 7.5 12 3l8.5 4.5L12 12z"/><path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z"/><path d="m3.5 7.5 8.5 4.5 8.5-4.5M12 12v9"/>',
    "external": '<path d="M14 4.5h5.5V10M19.5 4.5 11 13M17 14v5.5H4.5V7H10"/>',
    "key": '<circle class="duo" cx="8" cy="15" r="4"/><circle cx="8" cy="15" r="4"/><path d="m11 12 8.5-8.5M16.5 6.5l2.5 2.5M14.5 8.5l2 2"/>',
    "seal": '<path class="duo" d="M6 3h8l4 4v14H6z"/><path d="M6 3h8l4 4v14H6z"/><path d="m9 13.5 2 2 4-4"/>',
    "terminal": '<rect x="3" y="4.5" width="18" height="15" rx="1.5"/><path d="m7 9.5 3 2.5-3 2.5M12.5 15H17"/>',
    "track": '<path class="duo" d="M6.5 3.5h11v17L12 16.5l-5.5 4z"/><path d="M6.5 3.5h11v17L12 16.5l-5.5 4z"/><path d="M12 7v6M9 10h6"/>',
    "stop": '<rect x="6.5" y="6.5" width="11" height="11" rx="1"/>',
    "upload": '<path d="M7 18a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 18 10.5a3.75 3.75 0 0 1-.5 7.5"/><path d="M12 12.5v8M9 15.5l3-3 3 3"/>',
    "plug": '<path d="M9 3.5v4M15 3.5v4M6.5 7.5h11V11a5.5 5.5 0 0 1-11 0zM12 16.5V21"/><path d="m3.5 3.5 17 17"/>',
    "edit": '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>',
    "copy": '<rect x="8.5" y="8.5" width="11" height="11" rx="1.5"/><path d="M15.5 8.5v-3a1 1 0 0 0-1-1h-9a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h3"/>',
}


def icon(name, cls=""):
    return f'<svg class="i {cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">{ICONS[name]}</svg>'


SEV = {
    "critical": ("Critical", "Crit"),
    "high": ("High", "High"),
    "medium": ("Medium", "Med"),
    "low": ("Low", "Low"),
    "unknown": ("Unknown", "Unk"),
}
SEV_ORDER = ["critical", "high", "medium", "low", "unknown"]

# Direction A: one shape per level. Direction B: a 4-segment meter.
SEV_SHAPE_A = {
    "critical": '<path d="M8 1.5h8L22.5 8v8L16 22.5H8L1.5 16V8z"/>',
    "high": '<path d="M12 1.5 23 21.5H1z"/>',
    "medium": '<path d="M12 1 23 12 12 23 1 12z"/>',
    "low": '<circle cx="12" cy="12" r="9.5"/>',
    "unknown": '<circle class="hole" cx="12" cy="12" r="8.5"/><path d="M10.6 15.8h2.8v2.8h-2.8zM9 9.2a3 3 0 0 1 6 .2c0 2-2.6 2.3-2.6 4.6h-2.6c0-3 2.6-3.2 2.6-4.6a.4.4 0 0 0-.8 0z"/>',
}
SEV_FILLED_B = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def sev_shape_b(level):
    out = []
    for k, (x, h) in enumerate([(1, 8), (7, 12), (13, 16), (19, 20)]):
        cls = "" if k < SEV_FILLED_B[level] else ' class="hole"'
        out.append(f'<rect{cls} x="{x}" y="{22 - h}" width="4.5" height="{h}"/>')
    return "".join(out)


def sev_icons(level):
    return (f'<svg class="i only-a" viewBox="0 0 24 24" aria-hidden="true" focusable="false">{SEV_SHAPE_A[level]}</svg>'
            f'<svg class="i only-b" viewBox="0 0 24 24" aria-hidden="true" focusable="false">{sev_shape_b(level)}</svg>')


def sev_badge(level, text=None):
    full, _ = SEV[level]
    return f'<span class="sev sev-{level}">{sev_icons(level)}{E(text or full)}</span>'


def sev_counts(counts, extra=None, empty="None found"):
    parts = []
    for lvl in SEV_ORDER:
        n = counts.get(lvl, 0)
        if n:
            full, abbr = SEV[lvl]
            parts.append(f'<span class="sev sev-{lvl}" title="{n} {full.lower()}">{sev_icons(lvl)}{n}<span aria-hidden="true">&nbsp;{abbr}</span><span class="sr-only"> {full.lower()}</span></span>')
    if not parts:
        parts.append(f'<span class="none">{E(empty)}</span>')
    if extra:
        parts.append(f'<span class="extra">{icon("error")}{E(extra)}</span>')
    return '<span class="sevset">' + "".join(parts) + "</span>"


VERDICT_ICON = {"ok": "ok", "update": "update", "rebuild": "rebuild", "notbuilt": "notbuilt",
                "local": "upload", "error": "error", "running": "running", "muted": "skip"}


def verdict(kind, label):
    return f'<span class="verdict v-{kind}">{icon(VERDICT_ICON[kind])}{E(label)}</span>'


def btn(label, href, kind="", ico=None, disabled=False, extra=""):
    cls = "btn " + kind
    i = icon(ico) if ico else ""
    if disabled:
        return f'<a class="{cls.strip()}" role="link" aria-disabled="true" {extra}>{i}{E(label)}</a>'
    return f'<a class="{cls.strip()}" href="{href}" {extra}>{i}{E(label)}</a>'


# --------------------------------------------------------------------------- logos

LOGO_A = ('<svg class="logo only-a" viewBox="0 0 32 32" aria-hidden="true" focusable="false">'
          '<circle class="bgc" cx="16" cy="16" r="16"/>'
          '<path class="fg" d="M7.2 6.5c.5-.4 1.2-.3 1.6.2l3.6 4.3h7.2l3.6-4.3c.4-.5 1.1-.6 1.6-.2.3.2.5.6.4 1l-1 10.3c-.1.6-.3 1.1-.7 1.6l-5.9 6.3c-.8.9-2.2.9-3 0l-5.9-6.3c-.4-.5-.6-1-.7-1.6L6.8 7.5c-.1-.4.1-.8.4-1Z"/>'
          '<circle class="eye" cx="12.6" cy="15.6" r="1.35"/><circle class="eye" cx="19.4" cy="15.6" r="1.35"/>'
          '<path class="eye" d="M14.6 20.4h2.8L16 22.2z"/></svg>')
LOGO_B = ('<svg class="logo only-b" viewBox="0 0 32 32" aria-hidden="true" focusable="false">'
          '<path class="ln2" d="M1 1h30v30H1z"/>'
          '<path class="ln" d="M6.5 6 12 11.5h8L25.5 6l-1.2 11.5L16 26.5l-8.3-9z"/>'
          '<path class="ln" d="M11.5 15.5h3M17.5 15.5h3"/></svg>')

# --------------------------------------------------------------------------- data

LATEST = {
    "glibc": "2.43-r13", "glibc-locale-posix": "2.43-r13", "ld-linux": "2.43-r13",
    "libcrypto3": "3.6.5-r1", "libssl3": "3.6.5-r1", "openssl": "3.6.5-r1", "openssl-config": "3.3.0-r5",
    "zlib": "1.3.2.1_rc20260601-r0", "ca-certificates-bundle": "20260909-r2", "tzdata": "2026e-r0",
    "libgcc": "16.2.0-r1", "wolfi-baselayout": "20230201-r30", "bash": "5.3-r13", "busybox": "1.38.0-r2",
    "su-exec": "0.3-r4", "readline": "8.3-r3", "ncurses-terminfo-base": "6.6.20260926-r0",
    "libncursesw6": "6.6.20260926-r0", "icu-libs": "75.1-r42", "icu-data-full": "75.1-r42",
    "libxml2": "2.15.4-r0", "krb5-libs": "1.22.2-r4", "keyutils-libs": "1.6.3-r40", "libcom_err": "1.47.4-r2",
    "libverto": "0.3.2-r8", "libldap": "2.6.10-r5", "libuuid": "2.42.4-r0", "libzstd1": "1.5.7-r10",
    "gdbm": "1.26-r6", "pcre2": "10.49-r1", "libedit": "3.1-r19",
    "postgresql-17": "17.10-r1", "postgresql-17-client": "17.10-r1", "postgresql-17-contrib": "17.10-r1",
    "postgresql-17-oci-entrypoint": "17.10-r1",
    "postgresql-16": "16.14-r1", "postgresql-16-client": "16.14-r1", "postgresql-16-contrib": "16.14-r1",
    "postgresql-16-oci-entrypoint": "16.14-r1",
    "nginx-stable": "1.30.2-r0", "valkey-9.1": "9.1.2-r2",
}

OLD = {  # early September snapshot
    "wolfi-baselayout": "20230201-r28", "ca-certificates-bundle": "20260801-r0", "glibc": "2.43-r3",
    "glibc-locale-posix": "2.43-r3", "ld-linux": "2.43-r3", "libgcc": "16.1.0-r2", "libcrypto3": "3.6.3-r2",
    "libssl3": "3.6.3-r2", "openssl-config": "3.3.0-r5", "zlib": "1.3.2-r0", "tzdata": "2026b-r0",
    "bash": "5.3-r11", "busybox": "1.37.0-r60", "su-exec": "0.3-r4", "readline": "8.3-r2",
    "ncurses-terminfo-base": "6.5.20260704-r0", "libncursesw6": "6.5.20260704-r0", "icu-libs": "75.1-r40",
    "icu-data-full": "75.1-r40", "libxml2": "2.15.2-r1", "krb5-libs": "1.22.1-r2", "keyutils-libs": "1.6.3-r38",
    "libcom_err": "1.47.3-r1", "libverto": "0.3.2-r7", "libldap": "2.6.10-r3", "libuuid": "2.42.2-r0",
    "gdbm": "1.26-r5", "pcre2": "10.47-r0", "libedit": "3.1-r18",
}
MID = dict(OLD, **{  # mid September
    "glibc": "2.43-r10", "glibc-locale-posix": "2.43-r10", "ld-linux": "2.43-r10", "libgcc": "16.2.0-r0",
    "libcrypto3": "3.6.3-r4", "libssl3": "3.6.3-r4", "ca-certificates-bundle": "20260909-r1", "tzdata": "2026d-r0",
    "wolfi-baselayout": "20230201-r30", "busybox": "1.38.0-r1", "bash": "5.3-r12", "pcre2": "10.49-r0",
})
NEW = dict(LATEST)  # late September
NEW.update({"ncurses-terminfo-base": "6.6.20260912-r0", "libncursesw6": "6.6.20260912-r0", "libcrypto3": "3.6.5-r0",
            "libssl3": "3.6.5-r0", "glibc": "2.43-r12", "glibc-locale-posix": "2.43-r12", "ld-linux": "2.43-r12"})

BASE = ["wolfi-baselayout", "ca-certificates-bundle", "glibc", "glibc-locale-posix", "ld-linux", "libgcc",
        "libcrypto3", "libssl3", "openssl-config", "zlib"]
PG_DEPS = ["bash", "busybox", "su-exec", "readline", "ncurses-terminfo-base", "libncursesw6", "icu-libs",
           "icu-data-full", "libxml2", "krb5-libs", "keyutils-libs", "libcom_err", "libverto", "libldap",
           "libuuid", "tzdata", "libedit"]


def pkgset(snapshot, names, extra):
    out = [(n, snapshot[n]) for n in names]
    out += extra
    return sorted(out)


def pg_pkgs(major, ver, snap, more=()):
    tops = [(f"postgresql-{major}", ver), (f"postgresql-{major}-client", ver),
            (f"postgresql-{major}-contrib", ver), (f"postgresql-{major}-oci-entrypoint", ver)]
    return pkgset(snap, BASE + PG_DEPS + list(more), tops)


# Missing fixes: (severity, id, aliases, package(s), installed, fixed, reachable, severity source)
PG17_FIXES = [
    ("critical", "CVE-2026-85091", ["GHSA-g5fp-32jq-cfw2"], "zlib", "1.3.2-r0", "1.3.2.1_rc20260601-r0", True, "NVD · CVSS 4.0 9.3"),
    ("high", "CVE-2026-14456", ["GHSA-9x89-v382-mjh7"], "libcrypto3, libssl3", "3.6.3-r2", "3.6.3-r5", True, "NVD · CVSS 3.1 7.5"),
    ("high", "CVE-2026-5450", ["GHSA-829p-mc9m-7xhr"], "glibc", "2.43-r3", "2.43-r7", True, "NVD · CVSS 3.1 7.8"),
    ("medium", "CVE-2026-54876", ["GHSA-5cfw-78wc-wvjq"], "libcrypto3, libssl3", "3.6.3-r2", "3.6.3-r4", True, "NVD · CVSS 3.1 5.9"),
    ("medium", "CVE-2026-5928", ["GHSA-v898-xg3c-w4rj"], "glibc", "2.43-r3", "2.43-r7", True, "NVD · CVSS 3.1 5.5"),
    ("medium", "CVE-2026-4438", ["GHSA-935r-rfch-9mr7"], "glibc", "2.43-r3", "2.43-r4", True, "NVD · CVSS 3.1 5.3"),
    ("medium", "CVE-2026-4046", ["GHSA-g7c4-wv7q-gcc6"], "glibc", "2.43-r3", "2.43-r6", True, "NVD · CVSS 3.1 4.7"),
    ("low", "CVE-2026-4437", ["GHSA-m5wq-r4r4-4qrh"], "glibc", "2.43-r3", "2.43-r4", True, "NVD · CVSS 3.1 3.3"),
    ("unknown", "CVE-2026-6791", ["GHSA-ch73-g8qv-r6r5"], "glibc", "2.43-r3", "2.43-r10", True, "NVD: awaiting analysis"),
]
NGINX_FIXES = [
    ("critical", "CVE-2026-85091", ["GHSA-g5fp-32jq-cfw2"], "zlib", "1.3.2-r0", "1.3.2.1_rc20260601-r0", True, "NVD · CVSS 4.0 9.3"),
    ("high", "CVE-2026-14456", ["GHSA-9x89-v382-mjh7"], "libcrypto3, libssl3", "3.6.3-r4", "3.6.3-r5", True, "NVD · CVSS 3.1 7.5"),
]
OSSL35_FIXES = [
    ("high", "CVE-2026-14456", ["GHSA-9x89-v382-mjh7"], "openssl, libcrypto3, libssl3", "3.5.4-r0", "3.6.3-r5", False, "NVD · CVSS 3.1 7.5"),
    ("high", "CVE-2026-2673", ["GHSA-wj64-gh9j-xm82"], "openssl, libcrypto3, libssl3", "3.5.4-r0", "3.6.1-r3", False, "NVD · CVSS 3.1 7.4"),
    ("high", "CVE-2026-28386", [], "openssl, libcrypto3, libssl3", "3.5.4-r0", "3.6.2-r0", False, "NVD · CVSS 3.1 7.5"),
    ("medium", "CVE-2026-28387", [], "openssl, libcrypto3, libssl3", "3.5.4-r0", "3.6.2-r0", False, "NVD · CVSS 3.1 5.9"),
    ("medium", "CVE-2026-28388", [], "openssl, libcrypto3, libssl3", "3.5.4-r0", "3.6.2-r0", False, "NVD · CVSS 3.1 5.3"),
    ("medium", "CVE-2026-34180", [], "openssl, libcrypto3, libssl3", "3.5.4-r0", "3.6.3-r0", False, "NVD · CVSS 3.1 5.9"),
    ("low", "CVE-2026-28389", [], "openssl, libcrypto3, libssl3", "3.5.4-r0", "3.6.2-r0", False, "NVD · CVSS 3.1 3.7"),
    ("unknown", "CVE-2026-34181", [], "openssl, libcrypto3, libssl3", "3.5.4-r0", "3.6.3-r0", False, "NVD: awaiting analysis"),
]


def counts(fixes, reachable=True):
    c = {}
    for f in fixes:
        if f[6] == reachable:
            c[f[0]] = c.get(f[0], 0) + 1
    return c


def reg_image(component, version, created, ago, build=None, signed=None):
    d = dg(component + version + created)
    suffix = hashlib.sha1((component + version + created).encode()).hexdigest()[:6]
    return dict(version=version, tag=f"{version}-build-{suffix}", digest=d, created=created, ago=ago,
                ref=f"{REG_HOST}/{REG_REPO}/{component}", build=build, signed=signed)


def docker_image(name, version, created, ago, build=None):
    return dict(ref=f"lupetto/{name}:{version}-amd64", version=version, id=dg("docker" + name + version)[:19],
                created=created, ago=ago, build=build)


# Builds (newest first). stages: resolve, build, validate, load, publish, sign, attest
STAGES = [("resolve", "Resolve"), ("build", "Build"), ("validate", "Validate SBOM"), ("load", "Load into Docker"),
          ("publish", "Publish"), ("sign", "Sign"), ("attest", "Attest SBOM")]

BUILDS = []


def build(bid, product, track, apk, version, when, ago, outcome, stages, via, duration, note=None, **kw):
    b = dict(id=bid, product=product, track=track, apk=apk, version=version, when=when, ago=ago,
             outcome=outcome, stages=stages, via=via, duration=duration, note=note, **kw)
    BUILDS.append(b)
    return b


OKALL = {"resolve": ("ok", "3s"), "build": ("ok", "48s"), "validate": ("ok", "2s"), "load": ("skipped", "Not requested"),
         "publish": ("ok", "11s"), "sign": ("ok", "4s"), "attest": ("ok", "5s")}
LOCAL_ONLY = {"resolve": ("ok", "3s"), "build": ("ok", "52s"), "validate": ("ok", "2s"), "load": ("ok", "9s"),
              "publish": ("skipped", "Not requested"), "sign": ("skipped", "Not requested"), "attest": ("skipped", "Not requested")}

build("20261001-210214-nginx-stable", "nginx", "1.30", "nginx-stable", "1.30.2-r0", "2026-10-01 21:02 UTC", "2 min ago",
      "running", {"resolve": ("ok", "3s"), "build": ("ok", "41s"), "validate": ("ok", "2s"), "load": ("skipped", "Not requested"),
                  "publish": ("running", "Uploading layers · 38s"), "sign": ("pending", ""), "attest": ("pending", "")},
      "Explorer", "1m 24s so far", note="Rebuild to pick up 2 security fixes")
build("20260930-184410-openssl", "openssl", "3.6", "openssl", "3.6.5-r1", "2026-09-30 18:44 UTC", "yesterday",
      "partial", {"resolve": ("ok", "2s"), "build": ("ok", "22s"), "validate": ("ok", "1s"), "load": ("skipped", "Not requested"),
                  "publish": ("ok", "6s"), "sign": ("failed", "Cosign exited with status 1"), "attest": ("notattempted", "Needs a signed image")},
      "Explorer", "34s")
build("20260930-102233-valkey-9.1", "valkey", "9.1", "valkey-9.1", "9.1.2-r2", "2026-09-30 10:22 UTC", "yesterday",
      "ok", LOCAL_ONLY, "CLI", "1m 06s")
build("20260929-161502-busybox-static", "busybox-static", "1", "busybox-static", "1.38.0-r2", "2026-09-29 16:15 UTC", "2 days ago",
      "failed", {"resolve": ("ok", "2s"), "build": ("ok", "9s"), "validate": ("failed", "SBOM does not match the lock"),
                 "load": ("skipped", "Not requested"), "publish": ("notattempted", ""), "sign": ("notattempted", ""), "attest": ("notattempted", "")},
      "Explorer", "14s")
build("20260924-090112-postgresql-17", "postgresql", "17", "postgresql-17", "17.10-r0", "2026-09-24 09:01 UTC", "1 week ago",
      "ok", LOCAL_ONLY, "CLI", "1m 31s")
build("20260922-070405-postgresql-16", "postgresql", "16", "postgresql-16", "16.14-r1", "2026-09-22 07:04 UTC", "9 days ago",
      "ok", OKALL, "Explorer", "1m 12s")
build("20260920-113020-openssl", "openssl", "3.5", "openssl", "3.5.4-r0", "2026-09-20 11:30 UTC", "11 days ago",
      "ok", OKALL, "Explorer", "41s")
build("20260910-142251-nginx-stable", "nginx", "1.30", "nginx-stable", "1.30.2-r0", "2026-09-10 14:22 UTC", "3 weeks ago",
      "ok", OKALL, "Explorer", "58s")
build("20260903-061204-postgresql-17", "postgresql", "17", "postgresql-17", "17.9-r6", "2026-09-03 06:12 UTC", "4 weeks ago",
      "ok", OKALL, "Explorer", "1m 19s")
build("20260819-174455-postgresql-16", "postgresql", "16", "postgresql-16", "16.13-r7", "2026-08-19 17:44 UTC", "6 weeks ago",
      "ok", LOCAL_ONLY, "CLI", "1m 27s")
build("20260802-080014-postgresql-17", "postgresql", "17", "postgresql-17", "17.9-r3", "2026-08-02 08:00 UTC", "2 months ago",
      "ok", OKALL, "Explorer", "1m 22s")

BY_ID = {b["id"]: b for b in BUILDS}


def bpage(bid):
    return f"build-{bid}.html"


def start_page(track_key):
    return f"build-start-{track_key}.html"


# Tracks. key -> data
TRACKS = {}


def track(key, product, sel, apk, latest, latest_ago, state, label, why, action, registry, docker, builds,
          fixes=(), versions=(), sub=None, sub_warn=False, tags=(), error=None, unidentified=0):
    TRACKS[key] = dict(key=key, product=product, sel=sel, apk=apk, latest=latest, latest_ago=latest_ago,
                       state=state, label=label, why=why, action=action, registry=registry, docker=docker,
                       builds=builds, fixes=list(fixes), versions=list(versions), sub=sub, sub_warn=sub_warn,
                       tags=set(tags), error=error, unidentified=unidentified)


track("postgresql-17", "postgresql", "17", "postgresql-17", "17.10-r1", "2 days ago", "update", "Update available",
      "The registry's newest image is 17.9-r6. The index now has 17.10-r1, and rebuilding also picks up 9 security fixes in its packages.",
      ("Build 17.10-r1", start_page("postgresql-17"), "primary", "builds"),
      [reg_image("postgresql-17", "17.9-r6", "2026-09-03 06:13 UTC", "4 weeks ago", "20260903-061204-postgresql-17", True),
       reg_image("postgresql-17", "17.9-r3", "2026-08-02 08:01 UTC", "2 months ago", "20260802-080014-postgresql-17", True)],
      [docker_image("postgresql-17", "17.10-r0", "2026-09-24 09:02 UTC", "1 week ago", "20260924-090112-postgresql-17")],
      ["20260924-090112-postgresql-17", "20260903-061204-postgresql-17", "20260802-080014-postgresql-17"],
      fixes=PG17_FIXES,
      versions=["17.10-r1", "17.10-r0", "17.9-r7", "17.9-r6", "17.9-r5", "17.9-r4", "17.9-r3", "17.9-r0"],
      sub="17.9-r6 → 17.10-r1", tags=("action",), unidentified=2)
track("postgresql-16", "postgresql", "16", "postgresql-16", "16.14-r1", "2 days ago", "ok", "Up to date",
      "The registry has the newest 16.x version, and no known fixes are missing from its packages.",
      ("Details", "image-postgresql.html", "quiet", None),
      [reg_image("postgresql-16", "16.14-r1", "2026-09-22 07:05 UTC", "9 days ago", "20260922-070405-postgresql-16", True)],
      [docker_image("postgresql-16", "16.13-r7", "2026-08-19 17:45 UTC", "6 weeks ago", "20260819-174455-postgresql-16")],
      ["20260922-070405-postgresql-16", "20260819-174455-postgresql-16"],
      versions=["16.14-r1", "16.14-r0", "16.13-r7", "16.13-r6", "16.13-r5", "16.13-r4", "16.13-r3", "16.13-r2"],
      sub="16.14-r1", tags=("current",))
track("nginx-1.30", "nginx", "1.30", "nginx-stable", "1.30.2-r0", "3 weeks ago", "rebuild", "Rebuild for fixes",
      "Same nginx version, but 2 of its packages have security fixes in the index. A rebuild picks them up.",
      ("Rebuild", bpage("20261001-210214-nginx-stable"), "primary", "rebuild"),
      [reg_image("nginx-stable", "1.30.2-r0", "2026-09-10 14:23 UTC", "3 weeks ago", "20260910-142251-nginx-stable", True),
       reg_image("nginx-stable", "1.30.0-r1", "2026-07-14 09:30 UTC", "11 weeks ago", None, None)],
      [], ["20261001-210214-nginx-stable", "20260910-142251-nginx-stable"], fixes=NGINX_FIXES,
      versions=["1.30.2-r0", "1.30.1-r0", "1.30.0-r1", "1.30.0-r0"], sub="1.30.2-r0 · 2 fixes", tags=("action",))
track("valkey-9.1", "valkey", "9.1", "valkey-9.1", "9.1.2-r2", "1 week ago", "local", "Not published",
      "Built locally yesterday (9.1.2-r2) but not in the registry. Build and publish to share it.",
      ("Build & publish", start_page("valkey-9.1"), "primary", "upload"),
      [], [docker_image("valkey-9.1", "9.1.2-r2", "2026-09-30 10:23 UTC", "yesterday", "20260930-102233-valkey-9.1")],
      ["20260930-102233-valkey-9.1"],
      versions=["9.1.2-r2", "9.1.2-r1", "9.1.2-r0", "9.1.1-r2", "9.1.1-r1", "9.1.1-r0", "9.1.0-r4"],
      sub="Local 9.1.2-r2", tags=("action", "notbuilt"))
track("valkey-9.2", "valkey", "9.2", "—", None, None, "error", "Version not found",
      "The Wolfi index has no valkey 9.2 package yet. Available: 9.1, 9.0, 8.1.",
      ("Edit tracking", "track.html", "", "edit"), [], [], [],
      sub="No match in index", tags=("action",), error="No package matches valkey 9.2 in the current index.")
track("busybox-static-1", "busybox-static", "1", "busybox-static", "1.38.0-r2", "5 days ago", "notbuilt", "Not built",
      "No image yet. The last attempt failed during SBOM validation.",
      ("Build 1.38.0-r2", start_page("busybox-static-1"), "primary", "builds"), [], [], ["20260929-161502-busybox-static"],
      versions=["1.38.0-r2", "1.38.0-r1", "1.38.0-r0", "1.37.0-r61", "1.37.0-r60"],
      sub="Last attempt failed 2 days ago", sub_warn=True, tags=("action", "notbuilt"))
track("openssl-3.5", "openssl", "3.5", "openssl", "3.5.4-r0", "6 weeks ago", "ok", "Up to date",
      "The registry has the newest 3.5.x version. 8 fixes exist only in 3.6 — rebuilding 3.5 cannot pick them up.",
      ("Review fixes", "image-openssl-vulns-3.5.html", "quiet", None),
      [reg_image("openssl", "3.5.4-r0", "2026-09-20 11:31 UTC", "11 days ago", "20260920-113020-openssl", True)],
      [], ["20260920-113020-openssl"], fixes=OSSL35_FIXES,
      versions=["3.5.4-r0", "3.5.2-r1", "3.5.1-r1", "3.5.1-r0"], sub="8 fixes need 3.6", sub_warn=True, tags=("current",))
track("openssl-3.6", "openssl", "3.6", "openssl", "3.6.5-r1", "4 days ago", "ok", "Up to date",
      "The registry has the newest 3.6.x version. Its last build published the image but could not sign it.",
      ("View build", bpage("20260930-184410-openssl"), "quiet", None),
      [reg_image("openssl", "3.6.5-r1", "2026-09-30 18:44 UTC", "yesterday", "20260930-184410-openssl", False),
       reg_image("openssl", "3.6.4-r8", "2026-09-12 08:10 UTC", "3 weeks ago", None, None)],
      [], ["20260930-184410-openssl"],
      versions=["3.6.5-r1", "3.6.5-r0", "3.6.4-r8", "3.6.4-r7", "3.6.4-r6", "3.6.4-r5"], sub="Last build not signed", sub_warn=True,
      tags=("current",))

PRODUCTS = [
    dict(slug="postgresql", name="postgresql", desc="A sophisticated object-relational DBMS", mark="Pg",
         tracks=["postgresql-17", "postgresql-16"]),
    dict(slug="nginx", name="nginx", desc="HTTP and reverse proxy server (stable)", mark="Nx", tracks=["nginx-1.30"]),
    dict(slug="valkey", name="valkey", desc="Advanced key-value store", mark="Vk", tracks=["valkey-9.1", "valkey-9.2"]),
    dict(slug="busybox-static", name="busybox-static", desc="Swiss-army knife for embedded systems (static)", mark="Bb",
         tracks=["busybox-static-1"]),
    dict(slug="openssl", name="openssl", desc="The OpenSSL cryptography suite", mark="Ssl", tracks=["openssl-3.6", "openssl-3.5"]),
]
PBY = {p["slug"]: p for p in PRODUCTS}

# Package sets of images/builds we know about.
PKGS = {
    ("registry", "postgresql-17", "17.9-r6"): pg_pkgs(17, "17.9-r6", OLD, ["gdbm"]),
    ("local", "postgresql-17", "17.10-r0"): pg_pkgs(17, "17.10-r0", NEW, ["libzstd1"]),
    ("registry", "postgresql-16", "16.14-r1"): pg_pkgs(16, "16.14-r1", dict(NEW, **{"libcrypto3": "3.6.5-r0"})),
    ("local", "postgresql-16", "16.13-r7"): pg_pkgs(16, "16.13-r7", MID),
    ("registry", "nginx-1.30", "1.30.2-r0"): pkgset(MID, BASE + ["pcre2"], [("nginx-stable", "1.30.2-r0")]),
    ("registry", "openssl-3.5", "3.5.4-r0"): pkgset(dict(NEW, libcrypto3="3.5.4-r0", libssl3="3.5.4-r0"), BASE, [("openssl", "3.5.4-r0")]),
    ("registry", "openssl-3.6", "3.6.5-r1"): pkgset(dict(NEW, libcrypto3="3.6.5-r1", libssl3="3.6.5-r1"), BASE, [("openssl", "3.6.5-r1")]),
    ("local", "valkey-9.1", "9.1.2-r2"): pkgset(NEW, BASE, [("valkey-9.1", "9.1.2-r2")]),
}


def vkey(v):
    """Rough APK-ish ordering for sample data only."""
    import re
    parts = re.split(r"[.\-_r]+", v)
    out = []
    for p in parts:
        out.append((0, int(p)) if p.isdigit() else (1, p))
    return out


# --------------------------------------------------------------------------- page shell

SCREENS = [
    ("Images", [("Images (home)", "index.html"), ("Images · needs action filter", "index.html?show=action"),
                ("Images · a build is running", "index-building.html"), ("Images · nothing tracked yet", "index-empty.html"),
                ("Images · registry & Docker unreachable", "index-error.html"), ("Images · read-only server", "index-readonly.html")]),
    ("Image detail", [("postgresql · overview & versions", "image-postgresql.html"),
                      ("postgresql 17 · vulnerabilities", "image-postgresql-vulns-17.html"),
                      ("postgresql 17 · packages / SBOM", "image-postgresql-packages-17.html"),
                      ("postgresql · compare", "image-postgresql-compare.html"),
                      ("postgresql · builds", "image-postgresql-builds.html"),
                      ("nginx · rebuild for fixes", "image-nginx.html"),
                      ("openssl 3.5 · fixes need another version", "image-openssl-vulns-3.5.html"),
                      ("valkey · local only + version not found", "image-valkey.html"),
                      ("busybox-static · never built", "image-busybox-static.html")]),
    ("Catalog", [("Catalog", "catalog.html"), ("Catalog · search “postgres”", "catalog.html?q=postgres"),
                 ("Catalog · postgresql family", "catalog-postgresql.html")]),
    ("Builds", [("Builds", "builds.html"), ("Build · running", bpage("20261001-210214-nginx-stable")),
                ("Build · partial failure", bpage("20260930-184410-openssl")),
                ("Build · failed", bpage("20260929-161502-busybox-static")),
                ("Build · succeeded", bpage("20260922-070405-postgresql-16")),
                ("Build · just started", start_page("postgresql-17"))]),
    ("Dialogs", [("Track a product (no-JS page)", "track.html"), ("Track a product (dialog on Images)", "index.html#track")]),
]


def mockbar():
    screens = []
    for group, items in SCREENS:
        screens.append(f"<h4>{E(group)}</h4>")
        for label, href in items:
            screens.append(f'<a href="{href}">{E(label)}</a>')
    return f'''<div class="mockbar" role="region" aria-label="Mockup controls">
  <strong>Sample data</strong><span class="hide-sm">Design mockup — not the product UI. Data is illustrative.</span>
  <span class="spacer"></span>
  <span class="seg" aria-label="Visual direction">Direction:
    <a href="?theme=a" data-set-theme="a">A · Tana</a><a href="?theme=b" data-set-theme="b">B · Pista</a></span>
  <span class="seg" aria-label="Color mode">Mode:
    <a href="?mode=auto" data-set-mode="auto">Auto</a><a href="?mode=light" data-set-mode="light">Light</a><a href="?mode=dark" data-set-mode="dark">Dark</a></span>
  <details><summary>All screens ▾</summary><nav class="screens" aria-label="Mockup screens">{"".join(screens)}</nav></details>
</div>'''


ENV = {
    "ok": [("ok", "Registry", f"{REG_HOST}/{REG_REPO}"), ("ok", "Docker", "Connected"), ("ok", "Builds", "Enabled")],
    "readonly": [("ok", "Registry", f"{REG_HOST}/{REG_REPO}"), ("ok", "Docker", "Connected"), ("warn", "Builds", "Disabled · read-only")],
    "error": [("off", "Registry", "Unreachable"), ("off", "Docker", "Unavailable"), ("ok", "Builds", "Enabled")],
}


def layout(fname, title, active, body, env="ok", dialog="", running=True):
    nav = []
    for key, label, href, ico in [("images", "Images", "index.html", "images"), ("catalog", "Catalog", "catalog.html", "catalog"),
                                  ("builds", "Builds", "builds.html", "builds")]:
        cur = ' aria-current="page"' if key == active else ""
        count = '<span class="count" title="1 build running">1</span>' if key == "builds" and running else ""
        nav.append(f'<a href="{href}"{cur}>{icon(ico)}<span class="navtext">{label}</span>{count}</a>')
    envs = "".join(f'<span class="env-item"><span class="dot {"" if s == "ok" else s}" aria-hidden="true"></span>'
                   f'<span><span class="env-label">{E(k)}</span> <span class="only-a">·</span> {E(v)}</span></span>'
                   for s, k, v in ENV[env])
    page = f'''<!doctype html>
<html lang="en" data-theme="a" data-mode="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
<title>{E(title)} · Lupetto (mockup)</title>
<link rel="stylesheet" href="assets/styles.css">
<script src="assets/mockup.js"></script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
{mockbar()}
<div class="shell">
<header class="topbar">
  <div class="masthead">
    <a class="brand" href="index.html">{LOGO_A}{LOGO_B}<span><span class="word">Lupetto</span><br class="only-a"><span class="tagline only-a">Wolfi images, kept current</span></span></a>
    <nav class="mainnav" aria-label="Main">{"".join(nav)}</nav>
    <div class="envbar" aria-label="Connections">{envs}</div>
  </div>
</header>
<div class="main-col">
<main id="main" class="content">
{body}
</main>
<footer class="foot">
  <span>Status checked 21:00 UTC (4 min ago) · <a href="{fname}">Check now</a></span>
  <span>Wolfi index <span class="mono">{INDEX_SHA[:12]}</span> · signature verified</span>
  <span>Security feed <span class="mono">{FEED_SHA[:12]}</span> · fetched 20:58 UTC</span>
  <span>x86_64 · Lupetto CLI 0.6 (sample)</span>
</footer>
</div>
</div>
{dialog}
</body>
</html>
'''
    (OUT / fname).write_text(page)


# --------------------------------------------------------------------------- shared fragments

def data_note(unevaluated=True):
    return f'''<details class="datanote" id="about-data">
  <summary>{icon("info")}<span><strong>About this security data.</strong> Fixes come from Wolfi’s public security feed. It isn’t a full vulnerability scan.</span><span class="more"><span class="open-l">What this means</span><span class="close-l">Hide</span></span></summary>
  <div class="note-body">
    <ul>
      <li><strong>Fixed issues only.</strong> Lupetto lists advisories that Wolfi has already fixed in a newer package. Issues without a fix yet are not listed, so “none found” does not mean “no vulnerabilities”.</li>
      <li><strong>Wolfi packages only.</strong> Software added outside Wolfi packages is not covered.</li>
      <li><strong>The feed is not signed.</strong> It is fetched over HTTPS from packages.wolfi.dev (unlike the package index, whose signature is verified).</li>
      <li><strong>Severity</strong> comes from NVD (CVSS) or GitHub/OSV advisories. Newly published advisories may show <em>Unknown</em> until they are scored; severity never changes a verdict.</li>
      {'<li><strong>1 feed entry could not be evaluated</strong> because its version is malformed (<span class="mono">opa-envoy 1.1.0-r1-r0</span>). It affects none of your images.</li>' if unevaluated else ''}
    </ul>
  </div>
</details>'''


def where_registry(t, compact=True):
    if t["state"] == "error" and not t["registry"]:
        return '<span class="where-line"><span class="none">—</span></span>'
    if not t["registry"]:
        return f'<span class="where-line">{icon("registry")}<span class="none">Not in registry</span></span>'
    r = t["registry"][0]
    more = f' · +{len(t["registry"]) - 1} older' if len(t["registry"]) > 1 else ""
    return f'<span class="where-line">{icon("registry")}<span class="ver">{r["version"]}</span></span><span class="verdict-sub">{r["ago"]}{more}</span>'


def where_local(t, docker_ok=True):
    lines = []
    if not docker_ok:
        lines.append(f'<span class="where-line">{icon("plug")}<span class="none">Docker unavailable</span></span>')
        if t["docker"] and t["docker"][0]["build"]:
            d = t["docker"][0]
            lines.append(f'<span class="verdict-sub">Last loaded: {d["version"]} ({d["ago"]})</span>')
    elif t["docker"]:
        d = t["docker"][0]
        lines.append(f'<span class="where-line">{icon("local")}<span class="ver">{d["version"]}</span></span><span class="verdict-sub">in Docker · {d["ago"]}</span>')
    if not lines:
        lines.append(f'<span class="where-line">{icon("local")}<span class="none">None</span></span>')
    return "".join(lines)


def track_row(t, *, building=None, docker_ok=True, registry_ok=True, readonly=False):
    sel = f'<span class="sel">{E(t["sel"])}</span><span class="sel-sub">{E(t["apk"])}</span>'
    latest = (f'<span class="ver">{t["latest"]}</span>'
              if t["latest"] else '<span class="muted">—</span>')
    reach = counts(t["fixes"], True)
    unreach = sum(1 for f in t["fixes"] if not f[6])
    extra = f"{unreach} need another version" if unreach else None
    if t["state"] in ("notbuilt", "local", "error") and not t["registry"]:
        fixes = '<span class="sevset"><span class="none">No registry image</span></span>'
    elif not registry_ok:
        fixes = '<span class="sevset"><span class="none">Unknown</span></span>'
    else:
        fixes = sev_counts(reach, extra)
    reg_down = not registry_ok and t["state"] != "error"
    if reg_down:
        v = verdict("muted", "Couldn’t check") + '<span class="verdict-sub">Registry unreachable</span>'
        reg = '<span class="where-line">' + icon("registry") + '<span class="none">Unknown</span></span>'
    else:
        v = verdict(t["state"], t["label"])
        if t["sub"]:
            v += f'<span class="verdict-sub{" warn" if t["sub_warn"] else ""}">{E(t["sub"])}</span>'
        reg = where_registry(t) if registry_ok else '<span class="where-line"><span class="none">—</span></span>'
    label, href, kind, ico = t["action"]
    if building == t["key"]:
        b = BY_ID["20261001-210214-nginx-stable"]
        act = btn("Building · Publish", bpage(b["id"]), "", "running")
    elif kind == "primary" and (building or readonly):
        reason = "Builds are disabled on this server" if readonly else "Another build is running"
        act = btn(label, "", kind, ico, disabled=True, extra=f'title="{reason}"') + f'<span class="btn-note">{reason}</span>'
    elif reg_down:
        act = ""
    else:
        act = btn(label, href, kind, ico)
    tags = " ".join(sorted(t["tags"]))
    return f'''<tr data-filter-row data-tags="{tags}">
  <td class="lead" data-label="Version">{sel}</td>
  <td data-label="Registry">{reg}</td>
  <td data-label="Local">{where_local(t, docker_ok)}</td>
  <td data-label="Latest in Wolfi">{latest}</td>
  <td class="wide" data-label="Missing fixes">{fixes}</td>
  <td class="wide" data-label="Verdict">{v}</td>
  <td class="action" data-label="">{act}</td>
</tr>'''


def product_card(p, **kw):
    rows = "".join(track_row(TRACKS[k], **kw) for k in p["tracks"])
    search = " ".join([p["name"], p["desc"]] + [TRACKS[k]["apk"] for k in p["tracks"]])
    n = len(p["tracks"])
    return f'''<li class="product" data-filter-item data-search="{E(search)}">
  <div class="product-head">
    <span class="pmark" aria-hidden="true">{p["mark"]}</span>
    <div><h2><a href="image-{p["slug"]}.html">{E(p["name"])}</a></h2><p class="desc">{E(p["desc"])}</p></div>
    <span class="meta">{n} tracked version{"s" if n > 1 else ""} · <a href="image-{p["slug"]}.html">Details</a></span>
  </div>
  <table class="tracks stackable">
    <thead><tr><th scope="col">Version</th><th scope="col">Registry</th><th scope="col">Local</th><th scope="col">Latest in Wolfi</th><th scope="col">Missing fixes</th><th scope="col">Verdict</th><th scope="col"><span class="sr-only">Action</span></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</li>'''


def track_form(in_dialog):
    head_close = ('<a class="iconbtn" href="index.html" data-closes aria-label="Close">' + icon("close") + "</a>")
    choices = [
        ("18", "postgresql-18", "18.6-r4", "Newest major", False, False),
        ("17", "postgresql-17", "17.10-r1", "Already tracked", True, True),
        ("16", "postgresql-16", "16.14-r1", "Already tracked", True, True),
        ("15", "postgresql-15", "15.6-r5", "Only 1 release in the index", False, False),
        ("14", "postgresql-14", "14.11-r6", "Only 1 release in the index", False, False),
    ]
    items = "".join(
        f'''<label class="choice"><input type="checkbox" name="selector" value="{s}"{" checked disabled" if dis else (" checked" if s == "18" else "")}>
  <span class="main">postgresql {s}</span><span class="side"><span class="ver">{v}</span><br>{E(note)}</span>
  <span class="sub mono">{n}</span></label>''' for s, n, v, note, chk, dis in choices)
    body = f'''<div class="sheet-head dialog-head">
    <div><h2 id="track-title">Track a product</h2><p class="muted small">Lupetto will watch these versions and tell you when to build, update, or rebuild.</p></div>
    {head_close}
  </div>
  <form method="get" action="index.html">
  <div class="sheet-body">
    <div class="field">
      <label for="track-package{"-d" if in_dialog else ""}">Wolfi package</label>
      <input class="input" id="track-package{"-d" if in_dialog else ""}" name="package" value="postgresql" list="pkg-suggest" autocomplete="off">
      <datalist id="pkg-suggest"><option value="postgresql"><option value="nginx"><option value="valkey"><option value="redis-operator"><option value="caddy"><option value="haproxy"><option value="traefik"></datalist>
      <span class="help">A package name or a provider, as listed in the <a href="catalog.html">catalog</a>.</span>
    </div>
    <fieldset class="field">
      <legend>Versions to track</legend>
      <div class="choice-list">{items}</div>
    </fieldset>
    <div class="field">
      <label for="track-custom{"-d" if in_dialog else ""}">Or a more specific version <span class="muted">(optional)</span></label>
      <input class="input mono" id="track-custom{"-d" if in_dialog else ""}" name="custom" placeholder="e.g. 17.10" inputmode="decimal">
      <span class="help">Lupetto always builds the newest release matching what you enter: “17” follows every 17.x, “17.10” stays on 17.10.x.</span>
    </div>
    <div class="preview" aria-live="polite"><strong>Will add</strong><ul><li>postgresql <strong>18</strong> → <span class="mono">postgresql-18 18.6-r4</span> (not built yet)</li></ul></div>
  </div>
  <div class="sheet-foot">
    <span class="left">Saved to products.yaml on the server.</span>
    <a class="btn" href="index.html" data-closes>Cancel</a>
    <button class="btn primary" type="submit" name="tracked" value="postgresql 18">{icon("track")}Track 1 version</button>
  </div>
  </form>'''
    if in_dialog:
        return f'<dialog id="track-dialog" aria-labelledby="track-title">{body}</dialog>'
    return f'<div class="sheet" role="region" aria-labelledby="track-title">{body}</div>'


# --------------------------------------------------------------------------- Images (home)

def images_page(fname, variant="normal"):
    building = "nginx-1.30" if variant == "building" else None
    docker_ok = variant != "error"
    registry_ok = variant != "error"
    readonly = variant == "readonly"
    head_btn = (btn("Track a product", "track.html", "primary", "plus", disabled=True,
                    extra='title="products.yaml is read-only" aria-describedby="ro-note"')
                if readonly else btn("Track a product", "track.html", "primary", "plus", extra='data-opens="track-dialog"'))
    banners = ""
    if variant == "error":
        banners = f'''<div class="banner error" role="alert">{icon("error", "i-lg")}<div class="body">
  <p><strong>Can’t reach the registry.</strong> {REG_HOST} refused the connection at 21:04 UTC, so Lupetto can’t tell what’s published or which fixes are missing. Index and local information below is current.</p>
  <p class="small muted">Check the registry address and that it is running. Lupetto retries on the next check.</p>
  <div class="actions">{btn("Check again", "index-error.html", "small", "rebuild")}<a class="btn quiet small" href="builds.html">Build history</a></div></div></div>
<div class="banner warn">{icon("plug", "i-lg")}<div class="body">
  <p><strong>Docker isn’t available.</strong> Local Docker images can’t be listed, so “Local” shows what Lupetto last loaded according to its build records. Builds don’t need Docker.</p></div></div>'''
    elif variant == "readonly":
        banners = f'''<div class="banner info" id="ro-note">{icon("lock", "i-lg")}<div class="body">
  <p><strong>Read-only server.</strong> Builds are disabled (the server was started without <span class="mono">--enable-builds</span>), and tracked products can’t be changed because <span class="mono">products.yaml</span> is read-only.</p>
  <p class="small muted">You can still browse images, vulnerabilities, packages, and build history.</p></div></div>'''
    elif variant == "building":
        banners = f'''<div class="banner info">{icon("running", "i-lg")}<div class="body">
  <p><strong>Building nginx 1.30 (1.30.2-r0)</strong> — publishing to the registry. One build runs at a time; other builds can start when it finishes.</p>
  <div class="actions"><a class="btn small" href="{bpage("20261001-210214-nginx-stable")}">View progress</a></div></div></div>'''

    flash = f'''<div class="banner ok flash" data-flash="tracked" hidden role="status">{icon("ok", "i-lg")}<div class="body"><p><strong>Now tracking <span data-flash-text></span>.</strong> Its status appears after the next check (about a minute).</p></div></div>'''

    if variant == "empty":
        content = f'''<div class="empty">
  <span class="art">{icon("images", "i-xl")}</span>
  <h2>No products tracked yet</h2>
  <p>Track a Wolfi package and the versions you care about. Lupetto then shows what’s in your registry and local Docker, and tells you when to build, update, or rebuild for security fixes.</p>
  <div class="actions">{btn("Track a product", "track.html", "primary", "plus", extra='data-opens="track-dialog"')}{btn("Browse the catalog", "catalog.html", "", "catalog")}</div>
  <p class="small">Popular: <a href="catalog-postgresql.html">postgresql</a> · <a href="catalog.html?q=nginx">nginx</a> · <a href="catalog.html?q=valkey">valkey</a> · <a href="catalog.html?q=caddy">caddy</a></p>
</div>'''
        summary = ""
        filters = ""
        lede = "Nothing tracked yet."
    else:
        cards = "".join(product_card(p, building=building, docker_ok=docker_ok, registry_ok=registry_ok, readonly=readonly)
                        for p in PRODUCTS)
        if registry_ok:
            summary = f'''<div class="summary-strip">
  <a href="{fname}?show=action"><span class="ico v-update">{icon("update")}</span><span><span class="n">5</span><br><span class="t">need action</span></span></a>
  <a href="{fname}?show=current"><span class="ico v-ok">{icon("ok")}</span><span><span class="n">3</span><br><span class="t">up to date</span></span></a>
  <a href="{fname}?show=notbuilt"><span class="ico v-notbuilt">{icon("notbuilt")}</span><span><span class="n">2</span><br><span class="t">not in registry</span></span></a>
  <a href="image-postgresql-vulns-17.html"><span class="ico sev-critical">{sev_icons("critical")}</span><span><span class="n">2</span><br><span class="t">images missing critical fixes</span></span></a>
</div>'''
        else:
            summary = ""
        filters = f'''<form class="toolbar" method="get" action="{fname}" role="search" data-filter-form>
  <label class="search">{icon("search")}<span class="sr-only">Search images</span><input type="search" name="q" placeholder="Search images or packages"></label>
  <fieldset class="segmented" aria-label="Show"><legend class="sr-only">Show</legend>
    <label><input type="radio" name="show" value="all" checked>All <span class="n">8</span></label>
    <label><input type="radio" name="show" value="action">Needs action <span class="n">5</span></label>
    <label><input type="radio" name="show" value="current">Up to date <span class="n">3</span></label>
    <label><input type="radio" name="show" value="notbuilt">Not in registry <span class="n">2</span></label>
  </fieldset>
  <noscript><button class="btn small" type="submit">Apply</button></noscript>
</form>'''
        content = f'''<ul class="products" data-filter-scope>{cards}</ul>
<div class="empty small-empty" data-filter-empty hidden><h2>No images match</h2><p>Try a different search or filter.</p><div class="actions"><a class="btn" href="{fname}">Clear filters</a></div></div>'''
        lede = f"5 products · 8 tracked versions · comparing <span class=\"mono\">{REG_HOST}/{REG_REPO}</span> with the Wolfi index"
    body = f'''{banners}{flash}
<div class="page-head">
  <div class="titles"><h1>Images</h1><p class="lede">{lede}</p></div>
  <div class="actions">{head_btn}</div>
</div>
{summary}
{filters}
{content}
<div class="stack after-list" id="about">{"" if variant == "empty" else data_note()}</div>'''
    dialog = "" if readonly else track_form(True)
    layout(fname, "Images", "images", body, env={"error": "error", "readonly": "readonly"}.get(variant, "ok"),
           dialog=dialog, running=variant in ("normal", "building", "readonly"))


# --------------------------------------------------------------------------- image detail

def detail_header(p, tab, sel=None):
    ts = [TRACKS[k] for k in p["tracks"]]
    nfix = sum(len([f for f in t["fixes"] if f[6]]) for t in ts)
    nall = sum(len(t["fixes"]) for t in ts)
    first_vuln = next((t for t in ts if t["fixes"]), ts[0])
    first_pk = next((t for t in ts if any(k[1] == t["key"] for k in PKGS)), ts[0])
    tabs = [("overview", "Overview & versions", f"image-{p['slug']}.html", None),
            ("vulns", "Vulnerabilities", f"image-{p['slug']}-vulns-{first_vuln['sel']}.html", nall),
            ("packages", "Packages / SBOM", f"image-{p['slug']}-packages-{first_pk['sel']}.html", None),
            ("compare", "Compare", f"image-{p['slug']}-compare.html", None),
            ("builds", "Builds", f"image-{p['slug']}-builds.html", len([b for b in BUILDS if b["product"] == p["slug"]]))]
    tabhtml = []
    for key, label, href, n in tabs:
        cur = ' aria-current="page"' if key == tab else ""
        cnt = ""
        if n:
            hot = " hot" if key == "vulns" and nfix else ""
            cnt = f' <span class="count{hot}">{n}</span>'
        tabhtml.append(f'<a href="{href}"{cur}>{E(label)}{cnt}</a>')
    chips = " ".join(f'<span class="chip mono">{E(t["sel"])} · {E(t["apk"] if t["latest"] else "not in index")}</span>' for t in ts)
    return f'''<nav class="crumbs" aria-label="Breadcrumb"><a href="index.html">Images</a><span aria-hidden="true">/</span><span aria-current="page">{E(p["name"])}</span></nav>
<div class="page-head">
  <div class="titles"><div class="title-row"><span class="pmark" aria-hidden="true">{p["mark"]}</span><h1>{E(p["name"])}</h1></div>
  <p class="lede">{E(p["desc"])} · <span class="mono">{REG_HOST}/{REG_REPO}</span></p>
  <p class="lede">Tracking {chips}</p></div>
  <div class="actions">{btn("Edit tracking", "track.html", "", "edit")}</div>
</div>
<nav class="tabs" aria-label="Image sections">{"".join(tabhtml)}</nav>'''


def track_selector(p, base, current):
    ts = [TRACKS[k] for k in p["tracks"]]
    if len(ts) < 2:
        return ""
    links = "".join(f'<a href="{base}-{t["sel"]}.html"{" aria-current=\"page\"" if t["sel"] == current else ""}>{E(p["name"])} {E(t["sel"])}</a>' for t in ts)
    return f'<nav class="segmented" aria-label="Version">{links}</nav>'


def overview_page(p):
    panels = []
    for k in p["tracks"]:
        t = TRACKS[k]
        label, href, kind, ico = t["action"]
        act = btn(label, href, kind, ico) if kind == "primary" else ""
        reach = counts(t["fixes"], True)
        unreach = sum(1 for f in t["fixes"] if not f[6])
        fixline = ""
        if t["registry"]:
            fixline = f'<div><span class="label">Missing fixes in newest registry image</span><div>{sev_counts(reach, f"{unreach} need another version" if unreach else None)}</div></div>'
        verdict_block = f'''<div class="verdict-block">
  <div>{verdict(t["state"], t["label"])}</div>
  <p class="why">{E(t["why"])}</p>
  {fixline}
  <div>{act}</div>
</div>'''
        if t["state"] == "error":
            panels.append(f'''<section class="card track-panel" aria-labelledby="t-{k}">
<div class="card-head"><h2 id="t-{k}">{E(p["name"])} {E(t["sel"])}</h2></div>
{verdict_block}
<div class="card-body"><div class="empty small-empty"><span class="art">{icon("error", "i-xl")}</span><h3>No valkey 9.2 in the Wolfi index</h3>
<p>Lupetto can’t build or compare this version until Wolfi publishes it. You can keep tracking it — it will start working once the package appears — or change it to an available version.</p>
<div class="actions">{btn("Stop tracking 9.2", "index.html", "", "close")}{btn("Edit tracking", "track.html", "quiet", "edit")}</div>
<p class="small">Available valkey versions: <span class="mono">9.1</span> (9.1.2-r2) · <span class="mono">9.0</span> (9.0.4-r0) · <span class="mono">8.1</span> (8.1.4-r0)</p></div></div>
</section>''')
            continue
        # where things are
        reg_items = "".join(f'''<li><div class="line1"><span class="ver">{r["version"]}</span>{"<span class=\"chip accent\">newest</span>" if i == 0 else ""}</div>
  <div class="line2">{r["ago"]} · <span class="digest">{short(r["digest"])}</span></div>
  <div class="line2">{"Signed + SBOM attested · " if r["signed"] else ("Not signed · " if r["signed"] is False else "")}{f'<a href="{bpage(r["build"])}">build record</a>' if r["build"] else "No build record on this server"}</div></li>'''
                            for i, r in enumerate(t["registry"]))
        if not reg_items:
            reg_items = '<li class="none">Nothing published yet.</li>'
        if t["unidentified"]:
            reg_items += f'<li class="none">{t["unidentified"]} older images without Lupetto labels (not analyzed)</li>'
        dock_items = "".join(f'''<li><div class="line1"><span class="ver">{d["version"]}</span></div>
  <div class="line2 mono">{E(d["ref"])}</div><div class="line2">{d["ago"]} · image {d["id"][7:19]}</div></li>''' for d in t["docker"]) or '<li class="none">No images in local Docker.</li>'
        brs = [BY_ID[b] for b in t["builds"]][:3]
        build_items = "".join(f'''<li><div class="line1">{build_outcome_badge(b)}<a href="{bpage(b["id"])}" class="ver">{b["version"]}</a></div>
  <div class="line2">{b["ago"]} · {E(build_outputs_short(b))}</div></li>''' for b in brs) or '<li class="none">No builds yet.</li>'
        # timeline
        regv = {r["version"] for r in t["registry"]}
        dockv = {d["version"] for d in t["docker"]}
        buildv = {BY_ID[b]["version"] for b in t["builds"]}
        tl = []
        for i, v in enumerate(t["versions"]):
            marks = []
            if i == 0:
                marks.append(f'<span class="mark latest">Latest</span>')
            if v in regv:
                marks.append(f'<span class="mark reg">{icon("registry")}Registry</span>')
            if v in dockv:
                marks.append(f'<span class="mark dock">{icon("local")}Docker</span>')
            if v in buildv and v not in regv and v not in dockv:
                marks.append(f'<span class="mark">{icon("record")}Build</span>')
            cls = " ".join(c for c in ["has" if (v in regv or v in dockv) else "", "latest" if i == 0 else ""] if c)
            tl.append(f'<li class="{cls}"><span class="node" aria-hidden="true"></span><span class="v">{v}</span><span class="marks">{"".join(marks)}</span></li>')
        panels.append(f'''<section class="card track-panel" aria-labelledby="t-{k}">
<div class="card-head"><h2 id="t-{k}">{E(p["name"])} {E(t["sel"])} <span class="muted small mono">{E(t["apk"])}</span></h2></div>
{verdict_block}
<div class="where">
  <section aria-label="Registry"><h3>{icon("registry")}Registry</h3><ul>{reg_items}</ul></section>
  <section aria-label="Local Docker"><h3>{icon("local")}Local Docker</h3><ul>{dock_items}</ul></section>
  <section aria-label="Local builds"><h3>{icon("record")}Recent builds</h3><ul>{build_items}</ul></section>
</div>
<div class="card-head"><h3>Versions in Wolfi <span class="muted small">newest first</span></h3></div>
<ol class="timeline" aria-label="{E(p["name"])} {E(t["sel"])} versions, newest first">{"".join(tl)}</ol>
</section>''')
    body = detail_header(p, "overview") + '<div class="stack-lg">' + "".join(panels) + "</div>"
    layout(f"image-{p['slug']}.html", p["name"], "images", body)


def build_outcome_badge(b):
    m = {"ok": ("ok", "Succeeded"), "running": ("running", "Running"), "partial": ("rebuild", "Partly succeeded"),
         "failed": ("error", "Failed")}
    k, l = m[b["outcome"]]
    if b["outcome"] == "partial":
        return f'<span class="verdict v-update">{icon("error")}{l}</span>'
    if b["outcome"] == "failed":
        return f'<span class="verdict v-error">{icon("fail")}{l}</span>'
    return verdict(k, l)


def build_outputs_short(b):
    s = b["stages"]
    out = []
    if s["load"][0] == "ok":
        out.append("loaded into Docker")
    if s["publish"][0] == "ok":
        out.append("published")
    if s["sign"][0] == "ok":
        out.append("signed")
    if b["outcome"] == "failed":
        bad = next(n for k, n in STAGES if s[k][0] == "failed")
        return f"failed at {bad.lower()}"
    if b["outcome"] == "running":
        return "publishing…"
    if b["outcome"] == "partial":
        return "published, signing failed"
    return ", ".join(out) or "built"


def vulns_page(p, t):
    reach = [f for f in t["fixes"] if f[6]]
    unreach = [f for f in t["fixes"] if not f[6]]
    allc = counts(t["fixes"], True)
    for f in unreach:
        allc[f[0]] = allc.get(f[0], 0)
    tiles = []
    rc = counts(t["fixes"], True)
    uc = counts(t["fixes"], False)
    for lvl in SEV_ORDER:
        n = rc.get(lvl, 0) + uc.get(lvl, 0)
        tiles.append(f'<div class="sev-tile{" zero" if not n else ""}"><span class="n">{n}</span>{sev_badge(lvl)}</div>')

    def rows(fixes):
        out = []
        for sev, vid, aliases, pkg, inst, fixed, ok, src in sorted(fixes, key=lambda f: SEV_ORDER.index(f[0])):
            how = (f'<span class="reach yes">{icon("rebuild")}Any new build</span>' if ok
                   else f'<span class="reach no">{icon("error")}Needs {E(fixed.split(".")[0] + "." + fixed.split(".")[1])}</span>')
            al = f'<span class="aliases">{" ".join(aliases)}</span>' if aliases else ""
            out.append(f'''<tr><td data-label="Severity">{sev_badge(sev)}<span class="aliases">{E(src)}</span></td>
<td class="lead" data-label="Advisory"><a class="vuln-id" href="https://nvd.nist.gov/vuln/detail/{vid}" rel="noreferrer">{vid}</a>{al}</td>
<td data-label="Package"><span class="mono">{E(pkg)}</span></td>
<td data-label="Installed → fixed"><span class="ver">{inst}</span><span class="arrow" aria-hidden="true">→</span><span class="sr-only"> fixed in </span><span class="ver newer">{fixed}</span></td>
<td data-label="How to get it">{how}</td></tr>''')
        return "".join(out)

    head = '<thead><tr><th scope="col">Severity</th><th scope="col">Advisory</th><th scope="col">Package</th><th scope="col">Installed → fixed</th><th scope="col">How to get it</th></tr></thead>'
    img = t["registry"][0] if t["registry"] else None
    sections = []
    if not img:
        sections.append(f'''<div class="empty"><span class="art">{icon("shield", "i-xl")}</span><h2>No registry image to check</h2>
<p>Lupetto compares the newest image in your registry with the Wolfi security feed. {E(p["name"])} {E(t["sel"])} hasn’t been published yet.</p>
<div class="actions">{btn(t["action"][0], t["action"][1], "primary", t["action"][3]) if t["action"][2] == "primary" else ""}</div></div>''')
    else:
        label, href, kind, ico = t["action"]
        if reach:
            act = btn(label, href, "primary", ico) if kind == "primary" else ""
            sections.append(f'''<div class="banner warn">{icon("rebuild", "i-lg")}<div class="body"><p><strong>{len(reach)} fixes are available by rebuilding.</strong> {E(t["why"])}</p><div class="actions">{act}</div></div></div>''')
        elif not unreach:
            sections.append(f'''<div class="banner ok">{icon("ok", "i-lg")}<div class="body"><p><strong>No missing fixes found.</strong> The image has every fix that Wolfi’s feed lists for its packages. <a href="#about-data">What this does and doesn’t cover</a></p></div></div>''')
        sections.append(f'<div class="sev-tiles" aria-label="Missing fixes by severity">{"".join(tiles)}</div>')
        if reach:
            sections.append(f'''<div class="group-title"><h2>Fixed by rebuilding</h2><span class="hint">{len(reach)} advisories · the newer packages are already in the Wolfi index</span></div>
<div class="card"><table class="data stackable">{head}<tbody>{rows(reach)}</tbody></table></div>''')
        if unreach:
            sections.append(f'''<div class="group-title"><h2>Needs another version</h2><span class="hint">{len(unreach)} advisories · fixed only in a version outside {E(p["name"])} {E(t["sel"])}</span></div>
<div class="banner warn">{icon("error", "i-lg")}<div class="body"><p><strong>Rebuilding {E(p["name"])} {E(t["sel"])} won’t fix these.</strong> Wolfi lists the fix only in openssl 3.6. If 3.5 isn’t actually affected (for example, fixed by a backport), the feed can’t tell us, so treat these as “check before you rely on this version”.</p>
<div class="actions">{btn("See openssl 3.6", "image-openssl-vulns-3.6.html", "small")}</div></div></div>
<div class="card"><table class="data stackable">{head}<tbody>{rows(unreach)}</tbody></table></div>''')
    sel = track_selector(p, f"image-{p['slug']}-vulns", t["sel"])
    scope = (f'<p class="muted small">Newest registry image <span class="ver">{img["version"]}</span> · <span class="digest">{short(img["digest"])}</span> · built {img["ago"]}. Local images are not checked.</p>'
             if img else "")
    body = (detail_header(p, "vulns") + f'<div class="toolbar">{sel}</div>{scope}<div class="stack">' + "".join(sections)
            + data_note() + "</div>")
    layout(f"image-{p['slug']}-vulns-{t['sel']}.html", f"{p['name']} {t['sel']} vulnerabilities", "images", body)


def pkg_fname(p, t, si=0, sources=()):
    base = f"image-{p['slug']}-packages-{t['sel']}"
    return base + ".html" if si == 0 else f"{base}-{sources[si][0]}.html"


def packages_page(p, t, si=0):
    sources = [(kind, ver) for (kind, key, ver) in PKGS if key == t["key"]]
    sel = track_selector(p, f"image-{p['slug']}-packages", t["sel"])
    if not sources:
        body = detail_header(p, "packages") + f'''<div class="toolbar">{sel}</div><div class="empty"><span class="art">{icon("package", "i-xl")}</span><h2>No image to list packages for</h2>
<p>{E(p["name"])} {E(t["sel"])} has no image in the registry or in local builds yet. Once built, its installed packages and SPDX SBOM appear here.</p>
<div class="actions">{btn(t["action"][0], t["action"][1], "primary", t["action"][3]) if t["action"][2] == "primary" else ""}</div></div>'''
        layout(f"image-{p['slug']}-packages-{t['sel']}.html", f"{p['name']} {t['sel']} packages", "images", body)
        return
    kind, ver = sources[si]
    pk = PKGS[(kind, t["key"], ver)]
    fixed_pk = {}
    if kind == "registry":
        for f in t["fixes"]:
            for name in f[3].split(", "):
                fixed_pk[name] = fixed_pk.get(name, 0) + 1
    rows = []
    newer_n = 0
    for name, v in pk:
        lv = LATEST.get(name)
        newer = lv and lv != v and vkey(lv) > vkey(v)
        newer_n += 1 if newer else 0
        nf = fixed_pk.get(name)
        rows.append(f'''<tr data-filter-item data-search="{name}"><td class="lead" data-label="Package"><span class="mono">{name}</span></td>
<td data-label="Installed"><span class="ver">{v}</span></td>
<td data-label="Newer in Wolfi">{f'<span class="ver newer">{lv}</span>' if newer else '<span class="muted">—</span>'}</td>
<td data-label="Missing fixes">{f'<a href="image-{p["slug"]}-vulns-{t["sel"]}.html">{nf} advisor{"y" if nf == 1 else "ies"}</a>' if nf else '<span class="muted">—</span>'}</td></tr>''')
    src_links = []
    for k2, v2 in sources:
        lbl = f"Registry image {v2}" if k2 == "registry" else f"Local build {v2}"
        src_links.append(f'<a href="{pkg_fname(p, t, sources.index((k2, v2)), sources)}"{" aria-current=\"page\"" if (k2, v2) == (kind, ver) else ""}>{icon("registry" if k2 == "registry" else "record")} {E(lbl)}</a>')
    if kind == "local":
        bid = next(b for b in t["builds"] if BY_ID[b]["version"] == ver)
        sbom = f'''<div class="banner info">{icon("seal", "i-lg")}<div class="body"><p><strong>SPDX SBOM validated against the build’s lock.</strong> From local build {ver} ({BY_ID[bid]["ago"]}).</p>
<div class="actions"><a class="btn small" href="samples/{t["apk"]}-{ver}.spdx.json" download>{icon("download")}Download SPDX (JSON)</a><a class="btn quiet small" href="{bpage(bid)}">View build</a></div></div></div>'''
    else:
        img = t["registry"][0]
        bid = img["build"]
        sbom = f'''<div class="banner info">{icon("seal", "i-lg")}<div class="body"><p><strong>Packages read from the registry image</strong> <span class="digest">{short(img["digest"])}</span>. SBOM download from registry attestations comes later; {f'this image’s <a href="{bpage(bid)}">build record</a> has its SPDX file.' if bid else 'switch to a local build to download SPDX.'}</p>
{f'<div class="actions"><a class="btn small" href="samples/{t["apk"]}-{ver}.spdx.json" download>{icon("download")}Download SPDX from build record</a></div>' if bid else ""}</div></div>'''
    body = (detail_header(p, "packages") + f'''<div class="toolbar">{sel}<nav class="segmented" aria-label="Image">{"".join(src_links)}</nav></div>
{sbom}
<form class="toolbar" method="get" action="{pkg_fname(p, t, si, sources)}" role="search" data-filter-form>
  <label class="search">{icon("search")}<span class="sr-only">Filter packages</span><input type="search" name="q" placeholder="Filter {len(pk)} packages"></label>
  <span class="muted small">{len(pk)} packages · {newer_n} have newer versions in Wolfi</span>
</form>
<div class="card"><table class="data stackable"><thead><tr><th scope="col">Package</th><th scope="col">Installed</th><th scope="col">Newer in Wolfi</th><th scope="col">Missing fixes</th></tr></thead>
<tbody data-filter-scope>{"".join(rows)}</tbody></table></div>
<div class="empty small-empty" data-filter-empty hidden><p>No packages match “<span data-echo-q></span>”.</p></div>''')
    layout(pkg_fname(p, t, si, sources), f"{p['name']} {t['sel']} packages", "images", body)
    if si == 0:
        for extra in range(1, len(sources)):
            packages_page(p, t, extra)


def compare_page(p):
    if p["slug"] != "postgresql":
        body = detail_header(p, "compare") + f'''<div class="empty"><span class="art">{icon("compare", "i-xl")}</span><h2>Nothing to compare yet</h2>
<p>Compare needs two images of {E(p["name"])} — from the registry or local builds. {E(p["name"])} has {sum(len(TRACKS[k]["registry"]) for k in p["tracks"])} registry image(s) with readable packages.</p></div>'''
        layout(f"image-{p['slug']}-compare.html", f"{p['name']} compare", "images", body)
        return
    a = dict(PKGS[("registry", "postgresql-17", "17.9-r6")])
    b = dict(PKGS[("local", "postgresql-17", "17.10-r0")])
    fixes_by_pkg = {}
    for f in PG17_FIXES:
        for n in f[3].split(", "):
            fixes_by_pkg[n] = fixes_by_pkg.get(n, 0) + 1
    rows = []
    added = removed = changed = same = 0
    for name in sorted(set(a) | set(b)):
        va, vb = a.get(name), b.get(name)
        if va == vb:
            same += 1
            continue
        if va is None:
            added += 1
            kind = '<span class="chg add">+ Added</span>'
        elif vb is None:
            removed += 1
            kind = '<span class="chg rem">− Removed</span>'
        else:
            changed += 1
            kind = '<span class="chg up">↑ Upgraded</span>'
        nf = fixes_by_pkg.get(name)
        rows.append(f'''<tr><td class="lead" data-label="Package"><span class="mono">{name}</span></td><td data-label="Change">{kind}</td>
<td data-label="17.9-r6 (registry)"><span class="ver">{va or "—"}</span></td><td data-label="17.10-r0 (local build)"><span class="ver">{vb or "—"}</span></td>
<td data-label="Fixes gained">{f"{nf} advisor{'y' if nf == 1 else 'ies'}" if nf else '<span class="muted">—</span>'}</td></tr>''')
    opts_a = '<option selected>17.9-r6 · registry · 4 weeks ago</option><option>17.9-r3 · registry · 2 months ago</option><option>16.14-r1 · registry · 9 days ago</option>'
    opts_b = '<option selected>17.10-r0 · local build · 1 week ago</option><option>17.9-r6 · registry · 4 weeks ago</option><option>16.13-r7 · local build · 6 weeks ago</option>'
    body = detail_header(p, "compare") + f'''<div class="stack"><form class="card card-body compare-form" method="get" action="image-postgresql-compare.html">
  <div class="field"><label for="cmp-a">From</label><select class="input" id="cmp-a" name="from">{opts_a}</select></div>
  <span class="arrow" aria-hidden="true">{icon("compare")}</span>
  <div class="field"><label for="cmp-b">To</label><select class="input" id="cmp-b" name="to">{opts_b}</select></div>
  <button class="btn" type="submit">Compare</button>
</form>
<div class="section-head"><h2>17.9-r6 → 17.10-r0</h2><span class="hint">Registry image vs. local build</span></div>
<div class="diff-summary">
  <span class="diff-pill"><span class="chg add">+</span><strong>{added}</strong> added</span>
  <span class="diff-pill"><span class="chg rem">−</span><strong>{removed}</strong> removed</span>
  <span class="diff-pill"><span class="chg up">↑</span><strong>{changed}</strong> upgraded</span>
  <span class="diff-pill"><strong>{same}</strong> unchanged</span>
  <span class="diff-pill">{icon("shield")}<strong>9</strong> fixes gained</span>
</div>
<div class="card"><table class="data stackable"><thead><tr><th scope="col">Package</th><th scope="col">Change</th><th scope="col">17.9-r6 (registry)</th><th scope="col">17.10-r0 (local build)</th><th scope="col">Fixes gained</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
<p class="muted small">{same} packages are identical in both images and hidden. <a href="image-postgresql-compare.html">Show all</a></p></div>'''
    layout(f"image-{p['slug']}-compare.html", f"{p['name']} compare", "images", body)


def builds_table(bs, show_product=True):
    rows = []
    for b in bs:
        s = b["stages"]
        res = []
        for k, label in STAGES:
            st = s[k][0]
            res.append(st)
        rows.append(f'''<tr><td class="lead" data-label="Build"><a href="{bpage(b["id"])}"><strong>{E(b["apk"])} {b["version"]}</strong></a><span class="build-row-ref">{b["id"]}</span></td>
<td data-label="Outcome">{build_outcome_badge(b)}</td>
<td data-label="Result">{E(build_outputs_short(b))}</td>
<td data-label="Started">{b["when"][:16]}<span class="verdict-sub">{b["ago"]} · {b["duration"]}</span></td>
<td data-label="Started from">{E(b["via"])}</td></tr>''')
    return f'''<div class="card"><table class="data stackable"><thead><tr><th scope="col">Build</th><th scope="col">Outcome</th><th scope="col">Result</th><th scope="col">Started</th><th scope="col">Started from</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>'''


def product_builds_page(p):
    bs = [b for b in BUILDS if b["product"] == p["slug"]]
    content = builds_table(bs) if bs else f'''<div class="empty"><span class="art">{icon("builds", "i-xl")}</span><h2>No builds yet</h2><p>Builds started here or with the lupetto CLI on this machine appear in this list.</p></div>'''
    body = detail_header(p, "builds") + '<p class="muted small">History comes from build records kept in Lupetto’s cache, including builds run from the command line.</p>' + content
    layout(f"image-{p['slug']}-builds.html", f"{p['name']} builds", "images", body)


# --------------------------------------------------------------------------- builds

def published(b):
    for t in TRACKS.values():
        for r in t["registry"]:
            if r["build"] == b["id"]:
                return r
    return None


def btag(b):
    r = published(b)
    return r["tag"] if r else f'{b["version"]}-build-{hashlib.sha1(b["id"].encode()).hexdigest()[:6]}'


LOGS = {
    "20261001-210214-nginx-stable": [
        ("t", "21:02:14", "Resolving nginx 1.30 in the signed Wolfi index (x86_64)"),
        ("", "21:02:16", "index bad5600da4ee… signature verified (wolfi-signing.rsa.pub)"),
        ("ok", "21:02:17", "selected nginx-stable 1.30.2-r0"),
        ("", "21:02:17", "apko lock: 14 packages"),
        ("", "21:02:18", "apko build: installing wolfi-baselayout 20230201-r30, ca-certificates-bundle 20260909-r2, glibc 2.43-r13 …"),
        ("", "21:02:56", "apko build: layer sha256:5e2b9c… (11.4 MB)"),
        ("ok", "21:02:58", "SPDX validated against lock: 14/14 packages match"),
        ("", "21:02:58", "Docker load skipped (not requested)"),
        ("", "21:02:59", f"publishing {REG_HOST}/{REG_REPO}/nginx-stable:{btag(BY_ID['20261001-210214-nginx-stable'])}"),
        ("", "21:03:11", "uploading layer 1/1 …"),
    ],
    "20260930-184410-openssl": [
        ("t", "18:44:10", "Resolving openssl 3.6 in the signed Wolfi index (x86_64)"),
        ("ok", "18:44:12", "selected openssl 3.6.5-r1"),
        ("", "18:44:13", "apko lock: 11 packages"),
        ("ok", "18:44:35", "SPDX validated against lock: 11/11 packages match"),
        ("", "18:44:36", f"publishing {REG_HOST}/{REG_REPO}/openssl:{btag(BY_ID['20260930-184410-openssl'])}"),
        ("ok", "18:44:42", "published and read back: manifest, config and 1 layer verified"),
        ("", "18:44:42", "signing with Cosign v3.1.3 (key from LUPETTO_COSIGN_KEY)"),
        ("err", "18:44:44", "signing failed: cosign exited with status 1 (diagnostics discarded)"),
        ("", "18:44:44", "attestation not attempted: image is not signed"),
        ("err", "18:44:44", "build finished with a partial result; record written to failure.json"),
    ],
    "20260929-161502-busybox-static": [
        ("t", "16:15:02", "Resolving busybox-static 1 in the signed Wolfi index (x86_64)"),
        ("ok", "16:15:04", "selected busybox-static 1.38.0-r2"),
        ("", "16:15:04", "apko lock: 3 packages"),
        ("", "16:15:13", "apko build complete"),
        ("err", "16:15:15", "SPDX validation failed: SBOM lists 2 packages, lock has 3"),
        ("err", "16:15:15", "  missing from SBOM: wolfi-baselayout 20230201-r30"),
        ("err", "16:15:15", "stopped before publishing; record written to failure.json"),
    ],
}


def default_log(b):
    lines = [("t", b["when"][11:16] + ":00", f"Resolving {b['product']} {b['track']} in the signed Wolfi index (x86_64)"),
             ("ok", "", f"selected {b['apk']} {b['version']}"), ("", "", "apko lock and build complete"),
             ("ok", "", "SPDX validated against lock")]
    s = b["stages"]
    if s["load"][0] == "ok":
        lines.append(("ok", "", f"loaded lupetto/{b['apk']}:{b['version']}-amd64 into Docker"))
    if s["publish"][0] == "ok":
        lines.append(("ok", "", "published and read back (manifest, config, layers verified)"))
    if s["sign"][0] == "ok":
        lines.append(("ok", "", "signed image digest with Cosign"))
    if s["attest"][0] == "ok":
        lines.append(("ok", "", "attested SPDX to image digest"))
    lines.append(("ok", "", "result.json written"))
    return lines


STAGE_ICON = {"ok": "check", "failed": "fail", "running": "running", "pending": "pending", "skipped": "skip", "notattempted": "skip"}
STAGE_TEXT = {"ok": "Done", "failed": "Failed", "running": "In progress", "pending": "Waiting", "skipped": "Skipped",
              "notattempted": "Not attempted"}


def stage_list(stages):
    out = []
    for k, label in STAGES:
        st, detail = stages[k]
        out.append(f'''<li class="stage {st}"><span class="name">{icon(STAGE_ICON[st])}{E(label)}</span>
<span class="state">{STAGE_TEXT[st]}</span>{f'<span class="detail">{E(detail)}</span>' if detail and st != "ok" else (f'<span class="detail">{E(detail)}</span>' if detail else "")}</li>''')
    return f'<ol class="stages" aria-label="Build stages">{"".join(out)}</ol>'


def log_block(lines, open_=False):
    out = []
    for cls, ts, text in lines:
        t = f'<span class="t">{ts}</span> ' if ts else '         '
        out.append(f'{t}<span class="{cls if cls != "t" else ""}">{E(text)}</span>')
    return f'''<details class="raw"{" open" if open_ else ""}><summary>{icon("terminal")}Raw log</summary>
<pre class="log" tabindex="0" aria-label="Build log">{chr(10).join(out)}</pre></details>'''


def build_detail(b, started=False):
    s = b["stages"]
    tkey = next(k for k, t in TRACKS.items() if t["product"] == b["product"] and t["sel"] == b["track"])
    p = PBY[b["product"]]
    comp = b["apk"]
    reg = f"{REG_HOST}/{REG_REPO}/{comp}"
    dig = (published(b) or {}).get("digest") or dg(comp + b["version"] + b["id"])
    banner = ""
    actions = []
    if b["outcome"] == "running":
        banner = f'''<div class="banner info" role="status">{icon("running", "i-lg")}<div class="body"><p><strong>{"Starting" if started else "Publishing to the registry"}.</strong> {"Resolving the newest matching version in the signed Wolfi index." if started else "The image was built and its SBOM validated. Signing and SBOM attestation follow."} This page updates automatically.</p></div></div>'''
        actions.append(btn("Cancel build", "builds.html", "danger", "stop"))
    elif b["outcome"] == "partial":
        banner = f'''<div class="banner warn" role="alert">{icon("error", "i-lg")}<div class="body"><p><strong>Published, but not signed.</strong> The image is in the registry and verified, but Cosign could not sign it, so there is no signature or SBOM attestation. Anyone pulling <span class="mono">openssl:{btag(b)}</span> gets an unsigned image.</p>
<p class="small">Common causes: wrong key password (<span class="mono">COSIGN_PASSWORD</span>), an unreadable key file, or the signing service being unreachable. Cosign’s own messages are discarded so secrets can’t leak into logs.</p>
<div class="actions">{btn("Build again", start_page(tkey), "primary", "rebuild")}</div></div></div>'''
    elif b["outcome"] == "failed":
        banner = f'''<div class="banner error" role="alert">{icon("fail", "i-lg")}<div class="body"><p><strong>Failed while validating the SBOM.</strong> The image was built, but its SPDX SBOM doesn’t list every package in the lock, so Lupetto refused to publish it. Nothing was pushed or loaded.</p>
<p class="small">This usually means an apko or package issue rather than something you did. Retrying with a newer index may help; otherwise report it with the record below.</p>
<div class="actions">{btn("Try again", start_page(tkey), "primary", "rebuild")}{btn("Download record (failure.json)", "#", "small", "download")}</div></div></div>'''
    else:
        done = build_outputs_short(b)
        banner = f'''<div class="banner ok">{icon("ok", "i-lg")}<div class="body"><p><strong>Succeeded:</strong> {E(done)}.</p></div></div>'''
    out = []
    if s["publish"][0] == "ok":
        out.append(("Registry", f'<span class="mono">{reg}:{btag(b)}</span><br><span class="digest">{dig}</span>'))
    elif s["publish"][0] == "running":
        out.append(("Registry", f'<span class="mono">{reg}:{btag(b)}</span><br><span class="muted">Digest known after upload is verified</span>'))
    if s["load"][0] == "ok":
        out.append(("Docker", f'<span class="mono">lupetto/{comp}:{b["version"]}-amd64</span>'))
    if s["sign"][0] == "ok":
        out.append(("Signature", "Signed with Cosign key · SPDX attestation attached"))
    elif s["sign"][0] == "failed":
        out.append(("Signature", '<span class="reach no">' + icon("error") + "Not signed</span>"))
    if s["validate"][0] == "ok":
        out.append(("SBOM", f'<a href="samples/{comp}-{b["version"]}.spdx.json" download>{icon("download")} SPDX JSON</a> · validated against lock'))
    kv = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in out)
    lines = LOGS.get(b["id"]) or default_log(b)
    if started:
        lines = [("t", "21:05:12", f"Resolving {b['product']} {b['track']} in the signed Wolfi index (x86_64)"),
                 ("", "21:05:13", "fetching APKINDEX.tar.gz and wolfi-signing.rsa.pub …")]
    body = f'''<nav class="crumbs" aria-label="Breadcrumb"><a href="builds.html">Builds</a><span aria-hidden="true">/</span><span aria-current="page">{b["id"]}</span></nav>
{banner}
<div class="page-head">
  <div class="titles"><div class="title-row"><span class="pmark" aria-hidden="true">{p["mark"]}</span><h1>{E(b["apk"])} {b["version"]}</h1>{build_outcome_badge(b)}</div>
  <p class="lede">{E(b["note"] or f"{p['name']} {b['track']}")} · started {b["when"]} from {E(b["via"])} · {b["duration"]}</p></div>
  <div class="actions">{"".join(actions)}{btn(f"Open {p['name']}", f"image-{p['slug']}.html", "quiet")}</div>
</div>
<div class="stack">
<div class="card"><div class="card-body">{stage_list(s)}</div></div>
<div class="grid-2">
  <section class="card"><div class="card-body"><h2>Outputs</h2><hr class="sep"><dl class="kv">{kv or "<dt>Outputs</dt><dd class=\"muted\">None yet</dd>"}</dl></div></section>
  <section class="card"><div class="card-body"><h2>Inputs</h2><hr class="sep"><dl class="kv">
    <dt>Requested</dt><dd>{E(p["name"])} {E(b["track"])} (newest match)</dd>
    <dt>Selected</dt><dd><span class="mono">{E(b["apk"])} {b["version"]}</span> · x86_64</dd>
    <dt>Wolfi index</dt><dd><span class="mono">{INDEX_SHA[:16]}…</span> · signature verified</dd>
    <dt>Workspace</dt><dd><span class="mono">~/.cache/lupetto/builds/{b["id"]}</span></dd>
  </dl></div></section>
</div>
{log_block(lines, open_=b["outcome"] in ("failed",))}
</div>'''
    fname = start_page(tkey) if started else bpage(b["id"])
    layout(fname, f"Build {b['apk']} {b['version']}", "builds", body)


def builds_page():
    running = [b for b in BUILDS if b["outcome"] == "running"]
    r = running[0]
    rest = [b for b in BUILDS if b["outcome"] != "running"]
    body = f'''<div class="page-head"><div class="titles"><h1>Builds</h1><p class="lede">One build runs at a time. History comes from build records in Lupetto’s cache, so it includes builds run from the command line.</p></div></div>
<section class="card" aria-labelledby="now"><div class="card-head"><h2 id="now">Running now</h2></div>
<div class="card-body stack">
  <div class="outcome"><a href="{bpage(r["id"])}"><strong>{E(r["apk"])} {r["version"]}</strong></a>{build_outcome_badge(r)}<span class="muted small">{E(r["note"])} · started {r["ago"]}</span>
  <span class="spacer"></span>{btn("View", bpage(r["id"]), "small")}{btn("Cancel", "builds.html", "small danger", "stop")}</div>
  {stage_list(r["stages"])}
</div></section>
<div class="section-head"><h2>History</h2><span class="hint">{len(rest)} builds · newest first</span></div>
{builds_table(rest)}'''
    layout("builds.html", "Builds", "builds", body)


# --------------------------------------------------------------------------- catalog

CATALOG = [
    ("postgresql", "A sophisticated object-relational DBMS", [("18", "18.6-r4"), ("17", "17.10-r1"), ("16", "16.14-r1"), ("15", "15.6-r5"), ("14", "14.11-r6"), ("13", "13.14-r5"), ("12", "12.18-r4")], {"17", "16"}),
    ("nginx", "HTTP and reverse proxy server", [("1.31 mainline", "1.31.6-r2"), ("1.30 stable", "1.30.2-r0")], {"1.30 stable"}),
    ("valkey", "Advanced key-value store", [("9.1", "9.1.2-r2"), ("9.0", "9.0.4-r0"), ("8.1", "8.1.4-r0")], {"9.1"}),
    ("busybox-static", "Swiss-army knife for embedded systems (static)", [("1", "1.38.0-r2")], {"1"}),
    ("openssl", "The OpenSSL cryptography suite", [("3.6", "3.6.5-r1"), ("3.5", "3.5.4-r0"), ("3.4", "3.4.x"), ("3.3", "3.3.x"), ("3.0", "3.0.x")], {"3.6", "3.5"}),
    ("pgbouncer", "Lightweight connection pooler for PostgreSQL", [("1", "1.24.1-r3")], set()),
    ("caddy", "Fast and extensible multi-platform HTTP/1-2-3 web server with automatic HTTPS", [("2", "2.11.4-r0")], set()),
    ("haproxy", "A TCP/HTTP reverse proxy for high availability environments", [("3.4", "3.4.6-r1"), ("3.3", "3.3.10-r0"), ("3.2", "3.2.9-r0")], set()),
    ("traefik", "The Cloud Native Application Proxy", [("3.7", "3.7.4-r0"), ("3.6", "3.6.16-r0"), ("3.4", "3.4.5-r1"), ("3.3", "3.3.7-r0")], set()),
    ("mariadb", "The MariaDB open source relational database", [("11.8", "11.8.3-r0")], set()),
    ("mysql", "The MySQL open source relational database", [("9.4", "9.4.0-r1"), ("9.3", "9.3.0-r5"), ("9.1", "9.1.0-r5")], set()),
    ("memcached", "Distributed memory object caching system", [("1", "1.6.45-r5")], set()),
    ("rabbitmq-server", "Open source RabbitMQ core server", [("4.3", "4.3.1-r0"), ("4.2", "4.2.7-r0"), ("4.0", "4.0.9-r0")], set()),
    ("kafka", "Apache Kafka is a distributed event streaming platform", [("4.3", "4.3.0-r1"), ("4.2", "4.2.1-r0"), ("4.1", "4.1.1-r3")], set()),
    ("etcd", "A highly-available key value store for shared configuration", [("3.6", "3.6.12-r1")], set()),
    ("coredns", "CoreDNS is a DNS server that chains plugins", [("1.14", "1.14.3-r5"), ("1.13", "1.13.2-r4")], set()),
    ("envoy", "Cloud-native high-performance edge/middle/service proxy", [("1.36", "1.36.4-r0"), ("1.35", "1.35.6-r0"), ("1.34", "1.34.4-r1"), ("1.33", "1.33.3-r0")], set()),
    ("prometheus", "The Prometheus monitoring system and time series database", [("3.12", "3.12.0-r1"), ("3.11", "3.11.3-r4"), ("3.10", "3.10.0-r3")], set()),
    ("grafana", "The open and composable observability and data visualization platform", [("13.0", "13.0.2-r1"), ("12.4", "12.4.2-r6"), ("12.3", "12.3.2-r2")], set()),
    ("keycloak", "Open Source Identity and Access Management", [("26", "26.3.3-r0")], set()),
    ("nats-server", "High-Performance server for NATS.io", [("2", "2.15.0-r0")], set()),
    ("opensearch", "Open source distributed and RESTful search engine", [("3", "3.6.0-r5"), ("2", "2.18.0-r1")], set()),
    ("cassandra", "Open Source NoSQL Database", [("5.0", "5.0.8-r1"), ("4.1", "4.1.7-r0")], set()),
    ("clickhouse", "Fast, resource-efficient open-source analytical database", [("25.11", "25.11.9.34-r4"), ("25.10", "25.10.3.100-r1")], set()),
    ("zookeeper", "Distributed, highly available coordination service", [("3.9", "3.9.5-r4")], set()),
    ("tomcat", "Apache Tomcat Web Server", [("11.0", "11.0.26-r0")], set()),
    ("apache2", "Apache HTTP Server", [("2", "2.4.68-r3")], set()),
    ("python", "The Python programming language", [("3.14", "3.14.7_git20260925-r0"), ("3.13", "3.13.15_git20260925-r0")], set()),
    ("nodejs", "JavaScript runtime built on V8 engine", [("24", "24.21.0-r3")], set()),
    ("go", "The Go programming language", [("1.25", "1.25.12-r1")], set()),
    ("curl", "URL retrieval utility and library", [("8", "8.22.0-r3")], set()),
    ("sqlite", "C library which implements an SQL database engine", [("3", "3.53.4-r2")], set()),
]


def catalog_page():
    rows = []
    for name, desc, streams, tracked in CATALOG:
        chips = "".join(f'<span class="chip mono{" tracked" if s in tracked else ""}"{" title=\"Tracked\"" if s in tracked else ""}>{E(s)}{"<span class=\"sr-only\"> (tracked)</span>" if s in tracked else ""}</span>' for s, _ in streams)
        latest = streams[0][1]
        link = name == "postgresql"
        is_tracked = bool(tracked)
        acts = (btn("Open", f"image-{name}.html", "small") if is_tracked and name in PBY else btn("Track", "track.html", "small", "track", extra='data-opens="track-dialog"'))
        acts += btn("Build…", "catalog-postgresql.html" if link else "catalog-postgresql.html", "small quiet", "builds", extra='title="Choose a version to build once"')
        rows.append(f'''<tr data-filter-item data-search="{E(name + ' ' + desc)}" data-tags="{"tracked" if is_tracked else "untracked"}">
<td class="lead" data-label="Product">{'<a href="catalog-postgresql.html">' if link else ''}<strong class="mono">{E(name)}</strong>{'</a>' if link else ''}{" <span class=\"chip accent\">Tracked</span>" if is_tracked else ""}<span class="verdict-sub">{E(desc)}</span></td>
<td data-label="Versions in Wolfi"><span class="streams">{chips}</span></td>
<td data-label="Newest"><span class="ver">{E(latest)}</span></td>
<td class="actions-cell" data-label="">{acts}</td></tr>''')
    body = f'''<div class="page-head"><div class="titles"><h1>Catalog</h1><p class="lede">Every package in the signed Wolfi index (15,537 packages, x86_64). Track a product to watch it, or build any version once.</p></div></div>
<form class="toolbar" method="get" action="catalog.html" role="search" data-filter-form>
  <label class="search">{icon("search")}<span class="sr-only">Search the catalog</span><input type="search" name="q" placeholder="Search 15,537 Wolfi packages"></label>
  <fieldset class="segmented" aria-label="Show"><legend class="sr-only">Show</legend>
    <label><input type="radio" name="show" value="all" checked>All</label>
    <label><input type="radio" name="show" value="tracked">Tracked</label>
    <label><input type="radio" name="show" value="untracked">Not tracked</label>
  </fieldset>
  <noscript><button class="btn small" type="submit">Search</button></noscript>
</form>
<div class="card"><table class="data stackable"><thead><tr><th scope="col">Product</th><th scope="col">Versions in Wolfi</th><th scope="col">Newest</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
<tbody data-filter-scope>{"".join(rows)}</tbody></table></div>
<div class="empty small-empty" data-filter-empty hidden><h2>No packages match “<span data-echo-q></span>”</h2><p>Search matches package names, providers, and descriptions in the current index.</p></div>
<div class="pager"><span>Showing 32 popular products · related packages (e.g. <span class="mono">postgresql-17-client</span>) are listed on each product page</span><span><a class="btn small" href="catalog.html">Show all packages</a></span></div>'''
    layout("catalog.html", "Catalog", "catalog", body, dialog=track_form(True))


def catalog_family():
    streams = [("18", "postgresql-18", "18.6-r4", 19, None), ("17", "postgresql-17", "17.10-r1", 13, "postgresql-17"),
               ("16", "postgresql-16", "16.14-r1", 16, "postgresql-16"), ("15", "postgresql-15", "15.6-r5", 1, None),
               ("14", "postgresql-14", "14.11-r6", 1, None), ("13", "postgresql-13", "13.14-r5", 1, None), ("12", "postgresql-12", "12.18-r4", 1, None)]
    rows = []
    for s, name, latest, n, tk in streams:
        if tk:
            st = verdict(TRACKS[tk]["state"], TRACKS[tk]["label"])
            acts = btn("Open", "image-postgresql.html", "small") + btn("Build", start_page(tk), "small quiet", "builds")
        else:
            st = '<span class="muted small">Not tracked</span>'
            acts = btn("Track", "track.html", "small", "track", extra='data-opens="track-dialog"') + btn("Build once", start_page("postgresql-17"), "small quiet", "builds")
        stale = ' <span class="verdict-sub warn">Only 1 release in the index</span>' if n == 1 else ""
        rows.append(f'''<tr><td class="lead" data-label="Version"><strong class="mono">postgresql {s}</strong><span class="verdict-sub mono">{name}</span></td>
<td data-label="Newest"><span class="ver">{latest}</span>{stale}</td><td data-label="Releases in index">{n}</td><td data-label="Status">{st}</td><td class="actions-cell" data-label="">{acts}</td></tr>''')
    related = ["postgresql-17-client", "postgresql-17-contrib", "postgresql-17-oci-entrypoint", "postgresql-18-client", "pgbouncer"]
    versions17 = ["17.10-r1", "17.10-r0", "17.9-r7", "17.9-r6", "17.9-r5", "17.9-r4", "17.9-r3", "17.9-r0", "17.8-r2", "17.8-r0", "17.6-r1", "17.5-r3", "17.4-r0"]
    body = f'''<nav class="crumbs" aria-label="Breadcrumb"><a href="catalog.html">Catalog</a><span aria-hidden="true">/</span><span aria-current="page">postgresql</span></nav>
<div class="page-head"><div class="titles"><div class="title-row"><span class="pmark" aria-hidden="true">Pg</span><h1>postgresql</h1></div><p class="lede">A sophisticated object-relational DBMS · 7 major versions in the Wolfi index</p></div>
<div class="actions">{btn("Track versions", "track.html", "primary", "track", extra='data-opens="track-dialog"')}</div></div>
<div class="card"><table class="data stackable"><thead><tr><th scope="col">Version</th><th scope="col">Newest</th><th scope="col">Releases in index</th><th scope="col">Status</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<details class="raw"><summary>{icon("chev")}All 13 releases of postgresql 17</summary><p class="streams">{"".join(f'<span class="chip mono">{v}</span>' for v in versions17)}</p></details>
<p class="muted small">Related packages: {" · ".join(f'<span class="mono">{r}</span>' for r in related)}</p>'''
    layout("catalog-postgresql.html", "postgresql · Catalog", "catalog", body, dialog=track_form(True))


def track_page():
    body = f'''<nav class="crumbs" aria-label="Breadcrumb"><a href="index.html">Images</a><span aria-hidden="true">/</span><span aria-current="page">Track a product</span></nav>
{track_form(False)}'''
    layout("track.html", "Track a product", "images", body)


def write_samples():
    d = OUT / "samples"
    d.mkdir(exist_ok=True)
    for (kind, key, ver), pk in PKGS.items():
        apk = TRACKS[key]["apk"]
        doc = {
            "SPDX-ID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
            "name": f"sbom-{apk}-{ver} (SAMPLE — mockup data, not a real SBOM)",
            "documentNamespace": f"https://example.invalid/lupetto-mockup/{apk}-{ver}",
            "creationInfo": {"created": "2026-09-24T09:02:00Z", "creators": ["Tool: apko (sample)"]},
            "packages": [{"SPDXID": f"SPDXRef-Package-{n}", "name": n, "versionInfo": v,
                          "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                            "referenceLocator": f"pkg:apk/wolfi/{n}@{v}?arch=x86_64"}]} for n, v in pk],
        }
        (d / f"{apk}-{ver}.spdx.json").write_text(json.dumps(doc, indent=2) + "\n")
    for b in BUILDS:
        if b["stages"]["validate"][0] == "ok" and not (d / f"{b['apk']}-{b['version']}.spdx.json").exists():
            (d / f"{b['apk']}-{b['version']}.spdx.json").write_text(json.dumps({
                "spdxVersion": "SPDX-2.3", "name": f"sbom-{b['apk']}-{b['version']} (SAMPLE — mockup data)", "packages": []}, indent=2) + "\n")


def main():
    for f in OUT.glob("*.html"):
        f.unlink()
    images_page("index.html")
    images_page("index-building.html", "building")
    images_page("index-empty.html", "empty")
    images_page("index-error.html", "error")
    images_page("index-readonly.html", "readonly")
    for p in PRODUCTS:
        overview_page(p)
        for k in p["tracks"]:
            vulns_page(p, TRACKS[k])
            packages_page(p, TRACKS[k])
        compare_page(p)
        product_builds_page(p)
    for b in BUILDS:
        build_detail(b)
    for key, t in TRACKS.items():
        if t["latest"]:
            fake = dict(id=f"20261001-210512-{t['apk']}", product=t["product"], track=t["sel"], apk=t["apk"],
                        version=t["latest"], when="2026-10-01 21:05 UTC", ago="just now", outcome="running",
                        stages={"resolve": ("running", "Checking the signed index"), "build": ("pending", ""),
                                "validate": ("pending", ""), "load": ("skipped", "Not requested"), "publish": ("pending", ""),
                                "sign": ("pending", ""), "attest": ("pending", "")},
                        via="Explorer", duration="2s so far", note=None)
            build_detail(fake, started=True)
    builds_page()
    catalog_page()
    catalog_family()
    track_page()
    write_samples()


if __name__ == "__main__":
    main()
