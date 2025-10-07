Data Sources 
========================
# OpenPhish Feed (Free)
A feed of links confirmed to be Phishing links, should be immediately blocked

## Data format
Line separated list - Domains only

## Example
```
https://ipfs.io/ipfs/bafkreifrcxpdxwapa4yavggsonhfgcjwxitw5xvro4r6xzpsg47vzgx7d4
https://att-online-sign-odic.webflow.io/
https://chdpd.life/
```

## Limitations 
Updates once every 6 hours with a new list of urls

---

# OpenPhish Archival DB (Free, requires trial license)
Continuously updated archive of structured and searchable information on all the phishing websites detected by OpenPhish

## Data format
SQLite database with format of:
"asn","asn_name","brand","country_code","country_name","drop_accounts","host","ip","isotime","page_language","sector","ssl_cert_issued_by","ssl_cert_issued_to","ssl_cert_serial","tld","url","url_norm","url_page","url_path","url_query_string","url_scheme"


## Example
|asn    |asn_name       |brand         |country_code|country_name            |drop_accounts|host               |ip             |isotime             |page_language|sector           |ssl_cert_issued_by|ssl_cert_issued_to |ssl_cert_serial                     |tld |url                                                                         |url_norm                           |url_page       |url_path        |url_query_string                        |url_scheme|
|-------|---------------|--------------|------------|------------------------|-------------|-------------------|---------------|--------------------|-------------|-----------------|------------------|-------------------|------------------------------------|----|----------------------------------------------------------------------------|-----------------------------------|---------------|----------------|----------------------------------------|----------|
|AS51167|Contabo GmbH   |Mobile Legends|DE          |Germany                 |             |moobiileleginds.xyz|173.212.207.202|2020-12-28T00:57:23Z|en           |Gaming           |Let's Encrypt     |moobiileleginds.xyz|0407F0E97BC919ED41623B30B848BBA37037|xyz |https://moobiileleginds.xyz/                                                |https://moobiileleginds.xyz/       |               |/               |                                        |https     |
|AS22612|Namecheap, Inc.|Facebook, Inc.|US          |United States of America|             |emon-tb.shop       |198.54.116.51  |2020-12-28T00:57:23Z|None         |Social Networking|Sectigo Limited   |*.web-hosting.com  |D89EAF28184E981A84C854B782A2EC9E    |shop|http://emon-tb.shop/view-signin.php?facebook_com/marketplace/item/132610475=|http://emon-tb.shop/view-signin.php|view-signin.php|/view-signin.php|facebook_com/marketplace/item/132610475=|http      |


## Limitations 
Needs a license for usage, however the similar metadata can be extracted from the feed using external tools

---

# PhishTank Archival DB (Free)
Hourly updated archive of structured and searchable information on all the phishing websites detected by Archival DB, around 60k rows so far.
"If you do intend to fetch these files automatically, please register for an application key and see below for instructions on how to use it to request files. Without this key, you will be limited to a few downloads per day."

## Data format
JSON or CSV or XML database with format of:
phish_id ,url, phish_detail_url, submission_time, verified, verification_time, online, target

## Example
|phish_id|url                     |phish_detail_url                                         |submission_time          |verified|verification_time        |online|target                   |
|--------|------------------------|---------------------------------------------------------|-------------------------|--------|-------------------------|------|-------------------------|
|123456  |https://www.example.com/|http://www.phishtank.com/phish_detail.php?phish_id=123456|2009-06-19T15:15:47+00:00|yes     |2009-06-19T15:37:31+00:00|yes   |1st National Example Bank|



## Limitations 
* Might need an API key
* Always dumps all 60k+ entries

---

# URLhaus API
Dedicated to sharing malicious URLs that are being used for malware distribution

## Data format
JSON / CSV / TXT (feed/dump) with fields like:
`urlhaus_id, url, url_status, url_dateadded, url_lastseen, reporter, reporter_handle, verifier, threat, tags, file_md5, file_sha256, file_name, file_size, payload_type, distribution, asn, country, referrer, request_headers, response_code, cloaking, comments`


## Example

| urlhaus_id | url                                                                  | url_status | url_dateadded        | url_lastseen         | reporter | reporter_handle | verifier | threat           | tags        | file_md5                         | file_sha256                                                      | file_name | file_size | payload_type | distribution | asn     | country | referrer                                             | response_code | cloaking | comments                       |
| ---------- | -------------------------------------------------------------------- | ---------- | -------------------- | -------------------- | -------- | --------------- | -------- | ---------------- | ----------- | -------------------------------- | ---------------------------------------------------------------- | --------- | --------- | ------------ | ------------ | ------- | ------- | ---------------------------------------------------- | ------------- | -------- | ------------------------------ |
| 987654     | [http://malicious.example/abc.exe](http://malicious.example/abc.exe) | active     | 2025-09-30T08:12:00Z | 2025-10-06T14:05:00Z | Alice    | alice123        | Bob      | malware_download | exploit,win | d41d8cd98f00b204e9800998ecf8427e | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | abc.exe   | 124032    | exe          | hostingfarm  | AS13335 | US      | [http://referrer.example/](http://referrer.example/) | 200           | no       | served via shared hosting node |

## Limitations

* Some endpoints (submission/lookup) require an API key for authenticated actions; dumps are public but submissions use keys.
* Dumps/feeds are large — full CSV/JSON feeds contain many tens of thousands of records; plan storage and parsing accordingly.
* Feeds are refreshed on a schedule (dumps ~every 5 minutes; some derived signatures may update more/less frequently) — do **not** poll more often than the update cadence.
* Focused on **malware-distributing URLs** (malware_download); phishing/adware/redirect-only reports are not the primary coverage and may be excluded.
* Some fields may be empty or change after remediation (a URL can be listed while later cleaned).
* Derived feeds (RPZ, Snort/Suricata rules, hostfile) intentionally limit scope (recent/active only) and may exclude high-traffic/trusted domains to reduce false positives.


<div style="page-break-after: always;"></div>

# Additional Sources not mentioned in the document :
**THIS SECTION IS NOT MANUALLY VERIFIED, IT IS AI GENERATED**  

## Google Safe Browsing API (v4)

Summary:
The Google Safe Browsing API allows clients to check whether URLs are flagged as malicious (e.g. malware, phishing, unwanted software) by Google’s threat lists. It supports local list updates and server lookups for exact matches.

## Data format

Requests and responses are in **JSON** (or protobuf when using alternate media types) ([code.googlesource.com][1])

Key JSON structures / fields include:

* **FetchThreatListUpdatesRequest**:

  ```json
  {
    "client": {
      "clientId": "yourclient",
      "clientVersion": "1.0"
    },
    "listUpdateRequests": [
      {
        "threatType": "MALWARE",
        "platformType": "WINDOWS",
        "threatEntryType": "URL",
        "state": "<base64-encoded state>",
        "constraints": {
          "maxUpdateEntries": 1024,
          "maxDatabaseEntries": 2048,
          "region": "US",
          "supportedCompressions": ["RAW","RICE"]
        }
      }
    ]
  }
  ```

* **FetchThreatListUpdatesResponse**:

  ```json
  {
    "listUpdateResponses": [
      {
        "threatType": "MALWARE",
        "platformType": "WINDOWS",
        "threatEntryType": "URL",
        "responseType": "FULL_UPDATE" | "PARTIAL_UPDATE",
        "additions": {
          "compressionType": "RAW" | "RICE",
          "rawHashes": {
            "prefixSize": 4,
            "rawHashes": "<base64 string>"
          },
          "riceHashes": { … }   // optional compressed form
        },
        "removals": {
          "compressionType": "...",
          "rawIndices" / "riceIndices": { … }
        },
        "newClientState": "<base64>",
        "checksum": {
          "sha256": "<base64>"
        }
      }
    ],
    "minimumWaitDuration": "300.000s"
  }
  ```

* **FindThreatMatchesRequest**: check URLs against threat lists

  ```json
  {
    "client": { "clientId": "yourclient", "clientVersion": "1.0" },
    "threatInfo": {
      "threatTypes": ["MALWARE","SOCIAL_ENGINEERING"],
      "platformTypes": ["WINDOWS","ANDROID"],
      "threatEntryTypes": ["URL"],
      "threatEntries": [
        { "url": "http://bad.example.com/" },
        { "url": "http://phish.example.com/" }
      ]
    }
  }
  ```

* **FindThreatMatchesResponse**:

  ```json
  {
    "matches": [
      {
        "threatType": "MALWARE",
        "platformType": "WINDOWS",
        "threatEntryType": "URL",
        "threat": { "url": "http://bad.example.com/" },
        "threatEntryMetadata": {
          "entries": [
            { "key": "<base64>", "value": "<base64>" }
          ]
        },
        "cacheDuration": "300.000s"
      }
    ]
  }
  ```

* Hash lookup variant (**fullHashes.find**) uses **prefixes** in the request, and returns matching full hashes in the response. ([Google for Developers][2])

## Example

**Request: threatMatches.find**

```json
POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY  
Content-Type: application/json

{
  "client": {
    "clientId": "myApp",
    "clientVersion": "1.0"
  },
  "threatInfo": {
    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING"],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [
      { "url": "http://malicious.example/test.exe" }
    ]
  }
}
```

**Response (if match found):**

```json
{
  "matches": [
    {
      "threatType": "MALWARE",
      "platformType": "ANY_PLATFORM",
      "threatEntryType": "URL",
      "threat": {
        "url": "http://malicious.example/test.exe"
      },
      "threatEntryMetadata": {
        "entries": [
          {
            "key": "bWFsd2FyZV90eXBl",
            "value": "TUFMRVdBUl9EUk9QTw=="
          }
        ]
      },
      "cacheDuration": "300.000s"
    }
  ]
}
```

If **no matches** are found, `matches` is omitted or returns empty. ([Medium][3])

## Limitations

* **Non-commercial only**: The Safe Browsing API is free and intended for non-commercial use. Commercial users should migrate to Google’s **Web Risk** API. ([Google for Developers][4])
* **Quota limits**: There is a default usage quota; exceeding it requires applying for a higher quota via the Google Developer Console. ([Google for Developers][4])
* **Batch limits**: You can query up to 500 URLs per request in `FindThreatMatches`. ([Stack Overflow][5])
* **Cache & wait durations**: Responses may include `minimumWaitDuration` or `cacheDuration`, which require clients to delay further requests or cache negative results. ([code.googlesource.com][1])
* **Hash prefix ambiguity**: To reduce data transfer, clients download and compare hash *prefixes*, and only send full hashes when prefix matches occur. False positives at prefix level are resolved by full-hash checks. ([Google for Developers][2])
* **State synchronization & checksums**: Clients maintain a state per threat list. The server returns a checksum (SHA-256) of the sorted local database; mismatches force full resets. ([Google for Developers][2])
* **Does not expose full URL listings**: The API does *not* provide full dumps of malicious URLs; it is designed for match/lookup operations, not bulk download.
* **Cannot guarantee completeness**: Some malicious URLs may not yet be listed, or delays in propagation may occur. Always treat results as indicative, not definitive.
* **Policy & attribution**: If your application displays warnings to users, you must include qualifying language ("may be unsafe", etc.) and attribute “Advisory provided by Google.” ([Google for Developers][4])

[1]: https://code.googlesource.com/google-api-go-client/%2B/refs/heads/dartman/safebrowsing/v4/safebrowsing-api.json?autodive=0%2F&utm_source=chatgpt.com "safebrowsing/v4/safebrowsing-api.json - google-api-go-client"
[2]: https://developers.google.com/safe-browsing/v4/update-api "Safe Browsing Update API (v4)"
[3]: https://maxkleiner1.medium.com/google-safe-browsing-api-54e8303768d1 "Google Safe Browsing API. Build a Post | by Max Kleiner"
[4]: https://developers.google.com/safe-browsing/v4/usage-limits "Usage Restrictions | Safe Browsing APIs (v4)"
[5]: https://stackoverflow.com/questions/10855601/google-safebrowsing-api-limits "Google safebrowsing api limits"
 
 ---

## 2- Google Safe Browsing API v5

## Data format(s)

* Requests / responses are in **JSON** (REST) (or protobuf/alternate media types where supported). ([Google for Developers][6])
* Major JSON objects / entities include:

  * `HashLists` (list of available threat-hash lists) ([Dart packages][7])
  * `SearchHashesRequest / Response` — client sends hash prefixes, server returns matching full hashes and metadata. ([Go Packages][3])
  * `FullHash` objects (detailed match info) ([Dart packages][7])
  * Other metadata: list names, metadata, encoding (raw or compressed), etc. ([Dart packages][7])

In effect, you query by hash prefixes (local vs server synchronization), and the service returns matches or metadata.

---

## Examples

Here’s a conceptual example (not exact):

**Request** (search hashes)

```json
POST https://safebrowsing.googleapis.com/v5alpha1/hashes:search?key=API_KEY
Content-Type: application/json

{
  "hashPrefixes": [
    "abcd1234",   // prefix of SHA256 hashed URL expressions
    "ef01abcd"
  ]
}
```

**Response**

```json
{
  "fullHashes": [
    {
      "hash": "abcd1234ffff…",       // full hash
      "listName": "LIST_MALWARE",    // which threat list it matched
      "metadata": {
        "threatTypes": ["MALWARE"],
        "attributes": { … }
      }
    }
  ],
  "listMetadata": [
    {
      "listName": "LIST_MALWARE",
      "versions": [ … ],
      "threatEntryMetadata": { … }
    }
  ]
}
```

Also, v5 supports different **modes** (local cache + real-time check) and a new “Oblivious HTTP Gateway” to hide the client’s IP from Google. ([Google for Developers][9])

Clients maintain:

* A **Global Cache** of “likely benign” URL entries (as SHA256 hashed host-suffix / path-prefix expressions) locally. ([Google for Developers][9])
* A **set of threat lists** of hash prefixes (for host/path expressions) to check locally. ([Google for Developers][9])

When a URL is checked:

1. Check against local cache first.
2. If no match, check hash prefixes locally.
3. If prefix matches, call server to get full hash matches.
4. Apply verdict based on full match details.
   (If no match, considered safe — though “no listing” is not absolute guarantee.)
   ([Google for Developers][9])

Also, the **Oblivious HTTP Gateway API** is introduced in v5. It allows you to send requests through a third-party relay so that Google *does not see the originating client’s IP*. ([Google for Developers][9])

---

## Limitations

* It is still **non-commercial use only** (for commercial / revenue use, Google recommends **Web Risk** API) ([Google for Developers][6])
* As a hash-prefix / full hash model, there is inherent **trade-off between privacy and false positives/negatives**. Prefix-based checks may match many non-malicious items which are filtered by server full-hash lookup.
* Clients must **maintain state / sync**: Keep local caches, list versions, validate checksums, handle full resets if server signals mismatch.
* The **Oblivious HTTP Gateway** is optional, and it adds complexity (third-party relay) to hide IP addresses. ([Google for Developers][9])
* The API does **not expose full dumps** of malicious URLs; it is designed for matches / lookups, not bulk export.
* New threat types or metadata may be added in future minor versions, so client implementations must handle forward compatibility. ([Dart packages][7])
* Even with v5, **not every malicious URL is guaranteed listed** immediately — there is latency from detection, listing, propagation.
* Client implementations must respect **rate limits, minimum wait durations, cache durations** as dictated by responses.
* If clients skip updates or drift from server state and checksums no longer match, they may need full reinitialization (download full lists) — which is more expensive.


[6]: https://developers.google.com/safe-browsing/reference/rest "Safe Browsing API - Google for Developers"
[7]: https://pub.dev/documentation/googleapis/latest/safebrowsing_v5 "safebrowsing/v5 library - Pub.dev"
[8]: https://pkg.go.dev/google.golang.org/api/safebrowsing/v5 "safebrowsing package - google.golang.org/api/safebrowsing/v5"
[9]: https://developers.google.com/safe-browsing/reference "Overview | Google Safe Browsing"

---

## dnstwist
Summary: dnstwist generates domain name permutations (typosquats, homoglyphs, bitsquatting, etc.) for a target domain and optionally performs network/WHOIS checks on each candidate.

## Data format

Outputs: **CSV / JSON / SQLite / plain text**. Typical CSV/JSON fields:
`domain, fuzzer, score, distance, whois_registered, whois_registrar, whois_created, whois_updated, dns_a, dns_aaaa, dns_mx, dns_ns, dns_soa, http_status, http_server, http_title, redirect_to, geoip_country, asn, notes`

Example CSV header (single-line):
`domain,fuzzer,score,distance,whois_registered,whois_registrar,whois_created,whois_updated,dns_a,dns_mx,dns_ns,http_status,http_title,redirect_to,geoip_country,asn,notes`


## Example

| domain     | fuzzer    | score | distance | whois_registered |         dns_a | http_status | http_title     | redirect_to | geoip_country |     asn | notes                         |
| ---------- | --------- | ----: | -------: | ---------------: | ------------: | ----------: | -------------- | ----------- | ------------- | ------: | ----------------------------- |
| go0gle.com | homoglyph |  0.92 |        1 |              yes | 93.184.216.34 |         200 | Example Domain |             | US            | AS15133 | registered, likely typo-squat |


## Limitations

* Generates **candidates only** — presence in output ≠ maliciousness.
* Network checks (DNS/HTTP/WHOIS/GeoIP) require internet and can be rate-limited by remote services or blocked by firewalls/registrars.
* WHOIS data quality varies by TLD/registrar; some registries throttle or return limited data (GDPR redaction).
* May produce many false positives — further manual/automated analysis required.
* Some TLDs or IDN homoglyphs may be unsupported or handled imperfectly.
* Active detection (HTTP title/status) can be evaded by cloaking or CDN protection.
* Not a replacement for continuous monitoring — domains can be registered or change behavior after a scan.

---

## urlcrazy
Summary: urlcrazy enumerates likely typo, homoglyph, and permutation variants for a domain and reports DNS and HTTP resolution/status for each variant.

## Data format

Outputs: **CSV / plain text**. Typical fields:
`variant, permutation_type, is_registered, dns_a, dns_aaaa, dns_mx, http_status, http_title, http_server, redirect_to, resolved_ip, geoip_country, asn, notes`

Example CSV header (single-line):
`variant,permutation_type,is_registered,dns_a,dns_mx,http_status,http_title,redirect_to,resolved_ip,geoip_country,asn,notes`

## Example

| variant    | permutation_type | is_registered |         dns_a | http_status | http_title     | redirect_to | resolved_ip   | geoip_country |     asn | notes                  |
| ---------- | ---------------- | ------------: | ------------: | ----------: | -------------- | ----------- | ------------- | ------------- | ------: | ---------------------- |
| g00gle.com | typo (o→0)       |           yes | 93.184.216.34 |         200 | Example Domain |             | 93.184.216.34 | US            | AS15133 | likely typo-registered |

## Limitations

* Focuses on **enumeration** — does not label threats; human/ML vetting required.
* DNS/HTTP checks can be blocked by rate limits, CDNs, or defensive controls → incomplete results.
* WHOIS enrichment is limited (depends on separate lookups; not always included).
* Some permutation types (complex IDN homoglyphs) may be imperfectly generated.
* Not real-time—one-off scans may miss later registrations or changes.
* Running many lookups rapidly risks being throttled by DNS resolvers or remote services.
