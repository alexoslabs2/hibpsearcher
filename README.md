# hibpSearcher

**Overview**  
CLI tool to query the *Have I Been Pwned* (HIBP) database and identify in which breaches one or more email addresses were exposed. A practical deliverable for security investigations, due diligence, and incident validation — with a focus on stakeholder-readable output and easy ingestion into pipelines (CSV/JSON).

---

- Lists **all** breach sources returned by the API (Name / Domain / BreachDate / DataClasses / PwnCount / flags).  
- Complies with security and best practices (descriptive `User-Agent`, API key via environment variable, backoff on `429`).  
- Configurable output: **table**, **csv**, **json** (easy integration with BI / SIEM).  
- Basic email validation, duplicate removal, and clear logs for each queried email.

---

## Requirements
- Python 3.8+  
- Dependencies (install via pip):
```bash
pip install -r requirements.txt
# minimal requirements.txt:
# requests
```
- Valid HIBP API Key (create at https://haveibeenpwned.com/API/Key).

---

## Quick Setup
1. Clone / copy the repository.  
2. Install dependencies:
```bash
python3 -m pip install -r requirements.txt
```
3. Export your API Key:
```bash
export HIBP_API_KEY="your_key_here"
```

---

## Usage (example)
Create an `emails.txt` file with one email per line:
```
user1@example.com
user2@example.com
user3@example.com
```

Run:
```bash
python3 hibp.py --emails emails.txt --out table
```

Example output:
```
user1@example.com
Cit0day ['Email addresses', 'Passwords']

user2@example.com
Canva ['Email addresses', 'Geographic locations', 'Names', 'Passwords', 'Usernames']

user3@example.com
Cit0day ['Email addresses', 'Passwords']
```

Alternative output (CSV):
```bash
python3 hibp.py --emails emails.txt --out csv --csv-path results.csv
# generates: results.csv with columns (email, name, domain, breach_date, pwn_count, data_classes, ...)
```

Alternative output (JSON):
```bash
python3 hibp.py --emails emails.txt --out json > results.json
```

---

## Available Arguments
```
--emails    PATH    Text file with emails (required)
--out       FORMAT  Output: table (default) | csv | json
--csv-path  PATH    Path for CSV when --out=csv (default: hibp_results.csv)
--truncate          Uses truncateResponse=true (returns fewer fields)
```

## Example Integration in Pipeline (CI / SOC)
- Cron job triggers `hibp.py --emails /var/queue/new_emails.txt --out csv --csv-path /tmp/hibp_batch_$(date +%F).csv`  
- The CSV file is ingested into the SIEM / ticketing playbook for Active Response.
