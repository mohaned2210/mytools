#!/usr/bin/env python3
"""
gen_bruteforce_domains.py

Turn a list of deep (>=3 label) subdomains into a puredns brute-force base list.

For every input host we strip the left-most label one at a time and emit each
parent suffix, stopping BEFORE the 2-label registrable root. i.e. the "FUZZ"
position sits in front of each emitted line:

    input : 3zwaservp01.n0cosa.emac.cat.com
    FUZZ. 3zwaservp01.n0cosa.emac.cat.com   ->  3zwaservp01.n0cosa.emac.cat.com
    FUZZ. n0cosa.emac.cat.com               ->  n0cosa.emac.cat.com
    FUZZ. emac.cat.com                      ->  emac.cat.com
    (cat.com is the 2-label root -> NOT emitted)

The word "FUZZ" never appears in the output; puredns supplies it from the
wordlist. Output is lower-cased, de-duplicated and sorted.

Two classes of junk fuzz-zone are dropped by default:

  * IP-address hosts -- a leading IPv4 is stripped before suffixes are made, so
    `word.172.21.11.100.solar...` is never produced but the real parent zone is
    kept:
        172.21.11.100.solar.cat.com    ->  solar.cat.com     (dotted, 4 octets)
        113-61-129-201.veetime.cat.com ->  veetime.cat.com   (dash / rDNS)
        ip-10-0-0-1.foo.cat.com        ->  foo.cat.com        (AWS style)
    Disable with --keep-ip. A bare single numeric label (13.testaddon.example
    .com) is NOT an IP and is left alone.

  * www hosts -- any suffix whose left-most label is `www` / `wwwN` is dropped
    (`www.anchorcoupling.com` is a terminal web host, not a zone to fuzz under),
    but its real parent survives:
        www.aws.cat.com   -> dropped ;  aws.cat.com -> kept
    Disable with --keep-www.

Target-agnostic: nothing is hard-coded to a specific domain. The only per-target
knob is --min-labels (3 for 2-label roots like example.com; 4 for 3-label roots
like example.co.uk).

Usage:
    ./gen_bruteforce_domains.py [-i INPUT] [-o OUTPUT] [--min-labels N]
                                [--keep-ip] [--keep-www]
"""
import argparse
import re
import sys

# 0-255
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# a single label that is a dash/underscore-joined IPv4, optional ip- prefix
_DASH_IPV4 = re.compile(r"^(?:ip[-_])?" + _OCTET + r"(?:[-_]" + _OCTET + r"){3}$")
# www / www1 / www2 ... (www + optional digits only; NOT wwwtest / www-prod)
_WWW = re.compile(r"^www[0-9]*$")


def _is_octet(label):
    return label.isdigit() and len(label) <= 3 and int(label) <= 255


def strip_leading_ip(labels):
    """Drop a leading IPv4: dotted (4 octet labels) or a single dash-joined label.
    Loops so combos like <dashIP>.<dottedIP>.host also collapse. Returns new list."""
    labels = list(labels)
    while labels:
        if len(labels) >= 4 and all(_is_octet(x) for x in labels[:4]):
            del labels[:4]
            continue
        if _DASH_IPV4.match(labels[0]):
            del labels[0]
            continue
        break
    return labels


def suffixes(labels, min_labels):
    """Yield every dotted suffix (as a label list) with >= min_labels labels."""
    n = len(labels)
    if n < min_labels:
        return
    for i in range(0, n - min_labels + 1):
        yield labels[i:]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--input",
                    default="3_level_and_more_subdomains.txt",
                    help="input subdomain list (default: %(default)s)")
    ap.add_argument("-o", "--output",
                    default="puredns_bruteforce_domains.txt",
                    help="output base-domain list (default: %(default)s)")
    ap.add_argument("--min-labels", type=int, default=3,
                    help="smallest suffix (in labels) to emit; 3 keeps foo.cat.com "
                         "and stops before the 2-label root (default: %(default)s)")
    ap.add_argument("--keep-ip", action="store_true",
                    help="do NOT strip/skip IP-address hosts (keep raw junk)")
    ap.add_argument("--keep-www", action="store_true",
                    help="do NOT drop www/wwwN fuzz-zones")
    args = ap.parse_args()

    if args.min_labels < 2:
        ap.error("--min-labels must be >= 2 (2 would emit the bare registrable root)")

    out = set()
    dropped_www = set()
    read = skipped = ip_cleaned = 0
    try:
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                host = raw.strip().strip(".").lower()
                if not host:
                    continue
                read += 1
                labels = host.split(".")
                if "" in labels:                 # malformed (double dot etc.)
                    skipped += 1
                    continue

                if not args.keep_ip:
                    cleaned = strip_leading_ip(labels)
                    if cleaned != labels:
                        ip_cleaned += 1
                    labels = cleaned

                if len(labels) < args.min_labels:
                    skipped += 1
                    continue

                for sub in suffixes(labels, args.min_labels):
                    head = sub[0]
                    # left-most label is a dash-IPv4 -> junk zone to fuzz under
                    if not args.keep_ip and _DASH_IPV4.match(head):
                        continue
                    # left-most label is www / wwwN -> terminal web host, not a zone
                    if not args.keep_www and _WWW.match(head):
                        dropped_www.add(".".join(sub))
                        continue
                    out.add(".".join(sub))
    except FileNotFoundError:
        sys.exit(f"[!] input not found: {args.input}")

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted(out)) + "\n")

    print(f"[+] read {read} hosts "
          f"({ip_cleaned} had a leading IP stripped, "
          f"{len(dropped_www)} www zones dropped, {skipped} skipped)",
          file=sys.stderr)
    print(f"[+] wrote {len(out)} unique base domains -> {args.output}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
