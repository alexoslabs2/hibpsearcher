#!/usr/bin/env python3
# hibp_searcher.py — Have I Been Pwned Breach Finder
# Author: Alexos Core Labs
#
# Usage:
#   export HIBP_API_KEY="your_key_here"
#   python hibp_searcher.py --emails emails.txt --out csv
#
# Supported outputs: table (default), csv, json

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.parse
from typing import List, Dict, Any, Tuple

import requests

HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
HIBP_MIN_DELAY_SEC = 1.7  # Rate limit policy (~1.6s). Use 1.7s for safety margin.
USER_AGENT = "hibp-searcher/1.0 (alexos-core-labs; security-assessment)"

EMAIL_REGEX = re.compile(
    r"(?i)^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$"
)

def load_emails(path: str) -> List[str]:
    emails = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if EMAIL_REGEX.match(line):
                emails.append(line)
            else:
                print(f"[WARN] Ignored line (does not look like a valid email): {line}", file=sys.stderr)
    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for e in emails:
        if e.lower() not in seen:
            uniq.append(e)
            seen.add(e.lower())
    return uniq

def hibp_session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "hibp-api-key": api_key,
        "user-agent": USER_AGENT,
    })
    return s

def query_hibp_email(sess: requests.Session, email: str, truncate: bool = False, retries: int = 3) -> Tuple[int, Any]:
    """
    Returns (status_code, payload|None).
    200 => payload is a list of breaches
    404 => no breaches found
    401/403 => authentication/forbidden
    429 => rate limit (apply backoff and retry)
    Other 5xx => exponential retries
    """
    url = HIBP_URL.format(account=urllib.parse.quote(email))
    params = {"truncateResponse": str(truncate).lower()}
    attempt = 0
    backoff = 2.0

    while True:
        resp = sess.get(url, params=params, timeout=30)
        sc = resp.status_code

        if sc == 200:
            return sc, resp.json()
        if sc == 404:
            return sc, None
        if sc in (401, 403):
            # 401: Unauthorized (invalid key), 403: Forbidden (insufficient subscription)
            return sc, resp.text
        if sc == 429:
            # Too Many Requests — respect suggested backoff; if absent, use exponential backoff
            retry_after = resp.headers.get("Retry-After")
            wait = float(retry_after) if retry_after else backoff
            print(f"[WARN] 429 received. Backing off for {wait:.1f}s…", file=sys.stderr)
            time.sleep(wait)
            attempt += 1
            backoff = min(backoff * 2, 30.0)
            if attempt > retries:
                return sc, "Too many 429 responses; giving up."
            continue
        if 500 <= sc < 600:
            # Server errors
            attempt += 1
            if attempt > retries:
                return sc, f"Server error after {retries} retries."
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
            continue

        # Other codes
        return sc, resp.text

def normalize_records(email: str, breaches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extracts key fields from each breach for reporting.
    """
    norm = []
    for b in breaches:
        norm.append({
            "email": email,
            "name": b.get("Name"),
            "title": b.get("Title"),
            "domain": b.get("Domain"),
            "breach_date": b.get("BreachDate"),
            "added_date": b.get("AddedDate"),
            "modified_date": b.get("ModifiedDate"),
            "pwn_count": b.get("PwnCount"),
            "data_classes": b.get("DataClasses"),
            "is_verified": b.get("IsVerified"),
            "is_sensitive": b.get("IsSensitive"),
            "is_spam_list": b.get("IsSpamList"),
            "is_retired": b.get("IsRetired"),
        })
    return norm

def print_table(records: List[Dict[str, Any]]):
    if not records:
        print("No breaches found.")
        return
    # Concise and straightforward header
    cols = ["email", "name", "domain", "breach_date", "pwn_count", "is_verified", "data_classes"]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in records)) for c in cols}
    line = " | ".join(c.ljust(widths[c]) for c in cols)
    sep = "-+-".join("-"*widths[c] for c in cols)
    print(line)
    print(sep)
    for r in records:
        print(" | ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))

def write_csv(records: List[Dict[str, Any]], path: str = "hibp_results.csv"):
    if not records:
        print("[INFO] No breaches to write to CSV.")
        return
    cols = ["email","name","title","domain","breach_date","added_date","modified_date",
            "pwn_count","is_verified","is_sensitive","is_spam_list","is_retired","data_classes"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in records:
            w.writerow(r)
    print(f"[OK] CSV generated: {path}")

def main():
    parser = argparse.ArgumentParser(description="Query HIBP for breaches of a list of emails.")
    parser.add_argument("--emails", required=True, help="Text file with one email per line.")
    parser.add_argument("--out", choices=["table","csv","json"], default="table", help="Output format.")
    parser.add_argument("--csv-path", default="hibp_results.csv", help="(if --out=csv) Path for the output CSV file.")
    parser.add_argument("--truncate", action="store_true", help="Use truncateResponse=true (fewer fields).")
    args = parser.parse_args()

    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        print("ERROR: set the environment variable HIBP_API_KEY with your HIBP key.", file=sys.stderr)
        sys.exit(1)

    emails = load_emails(args.emails)
    if not emails:
        print("ERROR: no valid emails found.", file=sys.stderr)
        sys.exit(1)

    sess = hibp_session(api_key)
    all_records: List[Dict[str, Any]] = []

    for idx, e in enumerate(emails, start=1):
        sc, payload = query_hibp_email(sess, e, truncate=args.truncate)
        if sc == 200 and isinstance(payload, list) and payload:
            recs = normalize_records(e, payload)
            all_records.extend(recs)
            print(f"[{idx}/{len(emails)}] {e}: {len(recs)} breach source(s).")
        elif sc == 404:
            print(f"[{idx}/{len(emails)}] {e}: no breaches.")
        else:
            print(f"[{idx}/{len(emails)}] {e}: failure (HTTP {sc}) -> {payload}", file=sys.stderr)

        # Respect rate limit between account queries
        time.sleep(HIBP_MIN_DELAY_SEC)

    # Output
    if args.out == "table":
        print_table(all_records)
    elif args.out == "csv":
        write_csv(all_records, args.csv_path)
    else:  # json
        print(json.dumps(all_records, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()