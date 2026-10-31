# newsbot

A Telegram bot that watches security, tech and world news. Truly critical items reach you
as instant alerts, and everything else worth knowing arrives in a daily digest at 07:00
Kigali time. It costs $0: a public GitHub repo, free APIs and no AI calls.

**How a story travels:** Fetch → Normalize → Dedup → Score (0–10) → Route → Deliver

| Score | What happens |
|---|---|
| 7–10 | Instant alert |
| 3–6 | Added to the daily digest |
| 0–2 | Dropped |

## Setup

### 1. Create the bot and get its token

1. In Telegram, open a chat with **@BotFather** and send `/newbot`.
2. Choose a display name, then a username ending in `bot`.
3. BotFather replies with a token like `123456789:AAH...`. Treat it like a password.

### 2. Get your chat ID

1. Open a chat with your new bot and press **Start**, or send it any message. A bot cannot
   message you until you do this.
2. Open this address in your browser, using your own token:
   `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
3. Find `"chat":{"id":123456789` in the response. That number is your chat ID.

If the response is empty, send the bot another message and reload the page.

### 3. Optional free API keys

Both are optional. The bot works without them.

- **NVD API key** makes NVD lookups about 10 times faster.
  [Request one here](https://nvd.nist.gov/developers/request-an-api-key).
- **VulnCheck token** catches exploited vulnerabilities before CISA lists them. Create a
  free community account at [vulncheck.com](https://vulncheck.com), then generate a token.

### 4. Put the code on GitHub

Create a **public** repository (Actions minutes are free for public repos), then:

```bash
git init -b main
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

Everything in `state/` becomes public too. It holds only headlines, public links and CVE
IDs, never your secrets or chat ID.

### 5. Add the GitHub Secrets

In your repo, go to **Settings → Secrets and variables → Actions → New repository secret**:

| Secret | Required? |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Yes |
| `TELEGRAM_CHAT_ID` | Yes |
| `NVD_API_KEY` | No |
| `VULNCHECK_API_TOKEN` | No |

### 6. Do the first (seed) run

1. Open the **Actions** tab and enable workflows if GitHub asks.
2. Choose **Alerts → Run workflow**.
3. You should receive exactly one message: `✅ Bot initialized, monitoring N sources.`

That first run records everything currently in the feeds as already seen, so you are not
flooded with old news. From then on it runs by itself. **Check the run's log once**: any
line containing `FAILED` is a source blocking GitHub's servers (see Troubleshooting).

## Running it on your own computer

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

cp .env.example .env               # then fill in your values
set -a; source .env; set +a

python -m newsbot test-telegram                 # send one test message
python -m newsbot run --mode alerts --dry-run   # print messages; send and save nothing
python -m newsbot run --mode alerts             # the real thing
python -m newsbot run --mode digest             # send the digest now
python -m newsbot suggest-watchlist             # see "Keeping the watchlist current"
python -m pytest                                # run the tests (no network needed)
```

To try one feed alone: `python -m newsbot run --mode alerts --dry-run --source "Krebs on Security"`

A local real run writes to your local `state/`, separate from what GitHub Actions uses.
Use `--state-dir state-local` to keep them clearly apart (`state-*/` is git-ignored).

## Tuning

Everything lives in `config.yaml`, and each setting is commented there.

**Too many alerts?** Raise `settings.alert_threshold` to 8, or lower `max_alerts_per_run`.

**Too few alerts?** A single article about a Tier 1 zero-day scores 6 (keyword 3 + Tier 1
3), so it waits for a CVSS or EPSS signal or a third source before ringing. To alert on
it immediately, set `settings.alert_threshold: 6`.

**Change a source's influence:** its `weight` is added to every item's score from that
source. Hacker News has 3, so any story over 300 points reaches the digest. World feeds
have 1, so one further signal is enough.

**Turn a source off:** set `enabled: false`. A source you enable later starts silently
(its backlog is recorded, not sent), so adding feeds never floods you.

### Editing the watchlist

Each tier in `config.yaml` lists vendors. Only the highest matching tier counts.

```yaml
- vendor: Fortinet                    # any of these names is a match
  aliases: [Forti]
  products: [FortiGate, FortiOS]      # distinctive names that match on their own
  products_need_vendor: [Manager]     # ordinary words: count only beside the vendor name
  platforms: [Windows]                # match in news, but not on NVD records
```

### Keeping the watchlist current

```bash
python -m newsbot suggest-watchlist
```

This downloads the CISA KEV catalog and lists vendors with 2 or more additions in the last
12 months that you are not watching, with ransomware-linked counts. It only prints
suggestions and never edits your config. Running it every few months is plenty.

## Decisions where the brief was ambiguous

- **`weight` is additive.** The scoring rules had no place for it, and without it most
  tech and world stories could never reach 3. Security sources have 0, so it does not
  affect them.
- **`big_story` keywords are an addition.** Without them, a major world event scores only
  1, because reaching the coverage bonus needs near-identical headlines from 3 outlets,
  which rarely happens. Delete the list to turn this off.
- **Obscure CVEs are capped (`unmatched_vuln_cap`).** NVD publishes about 700 CVEs a day,
  and plain scoring would alert on any unknown plugin with CVSS 9+ and "unauthenticated" in
  its text. CVEs with no watchlist match and no exploitation signal are now dropped. Remove
  the setting to get strict scoring.
- **Mute words check the title only**, and never apply to KEV or NVD records. "Sponsored"
  does not fire on "state-sponsored", and "how to deal with" in a summary mutes nothing.
- **World feeds skip the watchlist.** "Apache", "Apple" and "Oracle" there are almost never
  security news. Regional keywords still apply.
- **Being added to KEV can alert a second time.** News never re-alerts on a CVE, but a CVE
  alerted for its CVSS that is later confirmed exploited sends one update. It is silent if
  a KEV alert (from VulnCheck, say) already went out.
- **Coverage can promote a story.** A digest item that gains enough sources becomes an alert
  and leaves the queue, so it is never delivered twice.
- **Fuzzy matching has guards.** Titles need at least 5 words, and the same outlet never
  counts as coverage of itself. Otherwise `token_set_ratio` scores any short title 100
  against every headline containing its words.
- **Failed alerts are retried.** An alert Telegram could not accept stays in
  `state/pending_alerts.json` until it is delivered.
- **The daily digest shows the top 15 per category.** The rest are counted, not listed.

## Limitations

- **GitHub cron is approximate.** Runs are often 5–30 minutes late, and GitHub may drop some
  under load, so "instant" means "usually within about 30 minutes". A missed digest is not
  lost: its queue goes out with the next one. A VPS removes this limit.
- **A pending digest can occasionally be replaced.** GitHub keeps only one waiting run per
  concurrency group. The queue is kept, so the worst case is a digest a day late.
- **Scheduled workflows stop after 60 days without repo activity.** The bot's own state
  commits normally prevent this. If it ever happens, re-enable it in the Actions tab.
- **State commits are frequent.** The NVD position changes on nearly every run, which means
  up to about 96 small commits a day. This is harmless, and it goes away on a VPS.
- **No Citrix, F5, SonicWall or Broadcom/VMware feeds.** None has a working public feed, so
  those vendors are covered through KEV, NVD and the news sources.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| No init message | Check the secrets' names and values, and that you pressed **Start** in the bot chat. |
| `chat not found` in the log | Wrong `TELEGRAM_CHAT_ID`, or you have not messaged the bot yet. |
| `Unauthorized` / `HTTP 401` | Wrong token. |
| `<source>: FAILED: ... HTTP 403` | That site blocks GitHub's servers. The rest keep working. Replace or disable it. |
| `seen.json is corrupt` | The bot stops rather than re-seed. Restore the file from git history. |
| Want to start over | Delete `state/seen.json`, `digest_queue.json` and `pending_alerts.json`, commit, and run Alerts. |

## Migrating to a VPS later

The code does not depend on GitHub Actions. Nothing outside `.github/` and
`scripts/commit_state.sh` knows about it.

1. **Install:** clone the repo, create a venv, `pip install -r requirements.txt`.
2. **Keep your history:** the `state/` folder comes with the clone, so nothing re-seeds.
3. **Secrets:** put them in `/etc/newsbot.env` with `chmod 600`.
4. **Stop GitHub:** disable the Alerts and Digest workflows, otherwise you get duplicates.
5. **Schedule with systemd:**

```ini
# /etc/systemd/system/newsbot-alerts.service
[Service]
Type=oneshot
User=newsbot
WorkingDirectory=/opt/newsbot
EnvironmentFile=/etc/newsbot.env
ExecStart=/opt/newsbot/.venv/bin/python -m newsbot run --mode alerts
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/newsbot/state
```

```ini
# /etc/systemd/system/newsbot-alerts.timer
[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
```

Create a matching digest service and timer with `--mode digest` and
`OnCalendar=*-*-* 07:00:00 Africa/Kigali`, then run
`systemctl enable --now newsbot-alerts.timer newsbot-digest.timer`.

**SQLite:** implement `load` and `save` on the `Storage` class in `newsbot/storage.py`, and
pass your class where `cli.py` creates `JsonStorage`. No other module touches storage.

**Bot commands:** add a new entry point that calls the existing functions in
`newsbot/pipeline.py`.

## Sources: changes from the brief

| Source | Status | Notes |
|---|---|---|
| Reuters | **Replaced by Al Jazeera** | `feeds.reuters.com` no longer resolves. Reuters and AP publish no free official RSS, so no true wire feed was available. Al Jazeera was chosen for its reputable world coverage, including Africa. |
| The Record | Found | `https://therecord.media/feed` |
| Dark Reading | Found | `https://www.darkreading.com/rss.xml` |
| CISA advisories | Found | `cybersecurity-advisories.xml` (1.3 MB). `all.xml` is 5.8 MB and mostly ICS advisories. |
| Microsoft MSRC | Found | `api.msrc.microsoft.com/update-guide/rss` |
| Cisco PSIRT | Found | `sec.cloudapps.cisco.com/.../CiscoSecurityAdvisory.xml` |
| Fortinet PSIRT | Found | `www.fortiguard.com/rss/ir.xml` |
| Palo Alto Networks | Found | `security.paloaltonetworks.com/rss.xml` |
| Ivanti | Found, with a caveat | Ivanti has no advisory feed, so this uses its security-advisory blog feed, mostly monthly updates. Emergency Ivanti issues will arrive through KEV, NVD and news. |
| **NCSC UK** | Added | National government CERT; often first to publish urgent guidance. |
| **Zero Day Initiative** | Added | Reputable vulnerability research covering many vendors on the watchlist. |
| **allAfrica Rwanda** | Added | Without it, little Rwandan news would appear in your feeds at all. |

The other URLs in the brief all worked unchanged.
