# n8n-nodes-isipsafe

Official [n8n](https://n8n.io) community node for [isIPsafe](https://isipsafe.com), the free IP reputation and abuse reporting service.

- **Check** whether an IP address is malicious before you trust it
- **Report** attackers from your logs, one at a time or 10,000 at once
- **Download the blocklist** in a firewall-ready format (nftables, ipset, nginx, Apache, MikroTik, STIX and more)

The node has no runtime dependencies and can be used as a tool by n8n AI agents.

## Installation

Follow the [community nodes installation guide](https://docs.n8n.io/integrations/community-nodes/installation/):

1. In n8n, open **Settings → Community Nodes**.
2. Select **Install**, enter `n8n-nodes-isipsafe` and confirm.
3. Search for **isIPsafe** in the nodes panel.

On a self-hosted instance without the UI you can also run `npm install n8n-nodes-isipsafe` inside `~/.n8n/nodes` and restart n8n.

## Credentials

Lookups (IP Check, Get Reports, Network Check Block and the category list) work **without a credential**, limited to 400 requests per day per server address. Reporting, bulk reporting, clearing reports and the blocklist need an API key, and a key raises the lookup limit to 10,000 per day.

1. Create a free account and API key at [isipsafe.com/login](https://isipsafe.com/login). Keys start with `sl_`.
2. In n8n, create a new **isIPsafe API** credential and paste the key.
3. Save. n8n tests the key with a single lookup.

The key is sent as an `Authorization: Bearer` header, never in the URL, so it stays out of proxy and server logs.

## Operations

| Resource  | Operation         | API key  | Output                                                                                        |
| --------- | ----------------- | -------- | --------------------------------------------------------------------------------------------- |
| IP        | **Check**         | optional | One item with the score, report counts, location, network and an added `isMalicious` field    |
| IP        | **Get Reports**   | optional | One item per report, newest first. Use _Return All_ or _Limit_                                |
| IP        | **Report**        | required | `ipAddress`, `abuseConfidenceScore`, `link`, `duplicate`                                      |
| IP        | **Clear Reports** | required | Removes the reports your account filed against an address                                     |
| Network   | **Check Block**   | optional | One item with the reported addresses inside a CIDR network (up to /16 or /48)                 |
| Blocklist | **Get**           | required | JSON: one item per address. Other formats: one item with the list as text or as a binary file |
| Bulk      | **Report**        | required | One item per upload with `savedReports` and `invalidReports`                                  |

### IP > Check and `isMalicious`

`isMalicious` is `true` only when the address **has reports**, is **not allowlisted** and its score is at or above the **Malicious Threshold** option (default 75). Well-known infrastructure such as public DNS resolvers is allowlisted and returns a score of 100 with no reports; the node never marks those as malicious. Options: _Malicious Threshold_, _Max Age (Days)_ (1 to 365, default 30) and _Include Reports_.

Typical use: **Webhook / log trigger → isIPsafe (IP > Check) → If `{{ $json.isMalicious }}` → block or alert**.

### IP > Report

Choose up to 12 categories from the list (loaded live from the API), or pass slugs or numeric IDs with an expression such as `ssh,brute-force`. _Comment_ is public, so leave out personal data; it is cut to 1,024 characters. _Attack Time_ defaults to now; times without a time zone are read as UTC. The target can be an address or a CIDR network up to a /24 (IPv4) or /56 (IPv6).

isIPsafe accepts one report per address every 15 minutes from the same account. A repeat is **not an error**: the node returns `{ "duplicate": true }` for that item.

### Bulk > Report

Every input item becomes one CSV row (`IP,Categories,ReportDate,Comment`). Map the four fields with expressions; the defaults read `{{ $json.ip }}` and `{{ $json.categories }}`. The rows are sent in uploads of up to 10,000, so a run with 25,000 items makes three uploads and returns three items, each paired with the input items it contains. Uploads are never retried automatically, to avoid duplicate reports.

Rows that fail validation (for example an invalid address) stop the node. With **Settings → On Error → Continue** they are skipped instead and listed in `skippedItems`.

### Blocklist > Get

Formats: JSON, plain text, CSV, STIX 2.1, ipset, nftables, nginx, Apache and MikroTik. Options: _Confidence Minimum_ (default 75), _Max Addresses_ (default 10,000, up to 500,000), _Max Age (Days)_ (1 to 90), _IP Version_, _Only Countries_ and _Except Countries_ (two-letter codes such as `CN,RU`). For formats other than JSON, choose whether the list goes into the `blocklist` text field or into a binary file, for example to write it to disk or upload it to a firewall.

## Categories

Common slugs: `ssh`, `brute-force`, `port-scan`, `web-app-attack`, `sql-injection`, `xss`, `vuln-scan`, `bad-bot`, `hacking`, `ddos`, `email-spam`, `phishing`, `malware-hosting`, `c2`, `open-proxy`, `vpn`. See the full list at [isipsafe.com/categories](https://isipsafe.com/categories).

## Errors, retries and rate limits

- Addresses and networks are validated before any request is made.
- Lookups time out after 10 seconds and are retried up to twice on network errors and 5xx responses. Reports, uploads and deletes are sent once.
- API errors show the message returned by isIPsafe, for example _Invalid API key_ (401) or an allowlisted or private address being reported (422).
- **Settings → On Error → Continue** returns an `error` field for the failing item and keeps going.

## Use with AI agents

The node is marked `usableAsTool`, so it can be attached to an **AI Agent** node. For example, give an agent the _IP > Check_ operation and let it fill the IP address from the conversation with `$fromAI()`.

## Compatibility

Built with `@n8n/node-cli` 0.54 and tested against n8n 2.x. Requires Node.js 22 or later.

## Development

```bash
npm install
npm run lint
npm run build
npm test
npm run dev   # starts n8n with this node loaded
```

Releases are published from GitHub Actions with npm provenance when a GitHub release is created (`.github/workflows/publish.yml`). The workflow uses npm trusted publishing; configure the repository as a trusted publisher for the package on npmjs.com.

## Links

- Official Usage Page: [isipsafe.com/integrations/n8n](https://isipsafe.com/integrations/n8n)
- npm Package: [npmjs.com/package/n8n-nodes-isipsafe](https://www.npmjs.com/package/n8n-nodes-isipsafe)
- Website: [isipsafe.com](https://isipsafe.com)
- API reference: [isipsafe.com/api](https://isipsafe.com/api)
- Integrations: [isipsafe.com/integrations](https://isipsafe.com/integrations)
- Security: see [SECURITY.md](SECURITY.md)

## License

[MIT](LICENSE). Data returned by the isIPsafe API is covered by the [isIPsafe EULA](https://isipsafe.com/eula).
