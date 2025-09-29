#!/usr/bin/env python3
# hibp_searcher.py — Have I Been Pwned Breach Finder
# Author: Alexos Core Labs
#
# Uso:
#   export HIBP_API_KEY="sua_chave_aqui"
#   python hibp_searcher.py --emails emails.txt --out csv
#
# Saídas suportadas: table (default), csv, json

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
HIBP_MIN_DELAY_SEC = 1.7  # Politica de rate limit (~1.6s). Use 1.7s p/ margem.
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
                print(f"[WARN] Linha ignorada (não parece e-mail válido): {line}", file=sys.stderr)
    # dedup preservando ordem
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
    Retorna (status_code, payload|None).
    200 => payload é lista de breaches
    404 => sem vazamentos
    401/403 => auth/forbidden
    429 => rate limit (faz backoff e tenta novamente)
    Outros 5xx => retries exponenciais
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
            # 401: Unauthorized (chave inválida), 403: Forbidden (assinatura inadequada)
            return sc, resp.text
        if sc == 429:
            # Too Many Requests — respeitar backoff sugerido; se não houver, usar exponencial
            retry_after = resp.headers.get("Retry-After")
            wait = float(retry_after) if retry_after else backoff
            print(f"[WARN] 429 recebido. Backoff {wait:.1f}s…", file=sys.stderr)
            time.sleep(wait)
            attempt += 1
            backoff = min(backoff * 2, 30.0)
            if attempt > retries:
                return sc, "Too many 429 responses; giving up."
            continue
        if 500 <= sc < 600:
            # Erros do servidor
            attempt += 1
            if attempt > retries:
                return sc, f"Server error after {retries} retries."
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
            continue

        # Outros códigos
        return sc, resp.text

def normalize_records(email: str, breaches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extrai campos chave de cada breach para reporting.
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
        print("Nenhum vazamento encontrado.")
        return
    # Cabeçalho enxuto e objetivo
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
        print("[INFO] Nenhum vazamento para escrever em CSV.")
        return
    cols = ["email","name","title","domain","breach_date","added_date","modified_date",
            "pwn_count","is_verified","is_sensitive","is_spam_list","is_retired","data_classes"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in records:
            w.writerow(r)
    print(f"[OK] CSV gerado: {path}")

def main():
    parser = argparse.ArgumentParser(description="Consulta vazamentos na HIBP para uma lista de e-mails.")
    parser.add_argument("--emails", required=True, help="Arquivo texto com um e-mail por linha.")
    parser.add_argument("--out", choices=["table","csv","json"], default="table", help="Formato de saída.")
    parser.add_argument("--csv-path", default="hibp_results.csv", help="(se --out=csv) Caminho do CSV de saída.")
    parser.add_argument("--truncate", action="store_true", help="Usa truncateResponse=true (menos campos).")
    args = parser.parse_args()

    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        print("ERRO: defina a variável de ambiente HIBP_API_KEY com sua chave da HIBP.", file=sys.stderr)
        sys.exit(1)

    emails = load_emails(args.emails)
    if not emails:
        print("ERRO: nenhum e-mail válido encontrado.", file=sys.stderr)
        sys.exit(1)

    sess = hibp_session(api_key)
    all_records: List[Dict[str, Any]] = []

    for idx, e in enumerate(emails, start=1):
        sc, payload = query_hibp_email(sess, e, truncate=args.truncate)
        if sc == 200 and isinstance(payload, list) and payload:
            recs = normalize_records(e, payload)
            all_records.extend(recs)
            print(f"[{idx}/{len(emails)}] {e}: {len(recs)} fonte(s) de vazamento.")
        elif sc == 404:
            print(f"[{idx}/{len(emails)}] {e}: nenhum vazamento.")
        else:
            print(f"[{idx}/{len(emails)}] {e}: falha (HTTP {sc}) -> {payload}", file=sys.stderr)

        # Respeita rate limit entre contas consultadas
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