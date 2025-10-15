# 📧 Email Monitoring Dashboard Guide

## Overview

The **Email Monitoring** tab is now the **primary dashboard** for the phishing detector. It provides comprehensive real-time monitoring of incoming emails, risk assessment, and detailed threat analysis.

## How to Access

### Start the Dashboard
```bash
# Option 1: Using run.py
python run.py dashboard

# Option 2: Direct command
python -m streamlit run app/dashboard/frontend.py
```

The dashboard will open at: **http://localhost:8501**

## Dashboard Layout

### 🎯 Navigation (Sidebar)
The Email Monitoring tab is now **FIRST** in the navigation (most prominent):

1. **📧 Email Monitoring** ← PRIMARY TAB
2. 📊 Threat Overview
3. 📈 Analytics
4. 🔍 Data Explorer
5. 🔎 Search

## Email Monitoring Tab Features

### 📊 Top-Level Metrics

Five key metrics displayed at the top:

| Metric | Description |
|--------|-------------|
| **Total Emails** | All emails in database + recent 24h count |
| **🚨 Critical Risk** | Emails with risk_score ≥ 85 + percentage |
| **⚠️ High Risk** | Emails with risk_score 70-84 + percentage |
| **📈 Avg Risk Score** | Average risk across all emails |
| **🔗 Threat Feed Matches** | URLs found in external threat feeds |

### 📈 Visualizations

#### 1. Risk Level Distribution (Pie Chart)
- Shows breakdown of Critical/High/Medium/Low risk emails
- Color-coded:
  - 🔴 Critical (85-100)
  - 🟠 High (70-84)
  - 🟡 Medium (50-69)
  - 🟢 Low (0-49)

#### 2. Email Timeline (Last 30 Days)
- Line chart showing:
  - Total emails received (blue area)
  - Critical risk emails (red dotted line)
  - High risk emails (orange dotted line)

### 📋 Email List

**Filter Controls:**
- **Minimum Risk Score**: Slider (0, 25, 50, 70, 85, 100)
- **Show Emails**: Dropdown (25, 50, 100, 200)
- **Sort By**: Risk Score or Date

**Table Columns:**
- **Risk Level**: Visual badge with score
  - 🚨 CRITICAL (85-100)
  - ⚠️ HIGH (70-84)
  - ⚡ MEDIUM (50-69)
  - ✓ LOW (0-49)
- **From**: Sender email address
- **Subject**: Email subject line
- **Received**: Timestamp
- **URLs**: Total number of URLs in email
- **Threats**: Number of URLs from threat feeds

### 📧 Email Details View

Select any email to see:

**Email Information:**
- Email ID
- Sender
- Date
- **Risk Score** (large, color-coded display)
- Total URLs count
- Threat Feed Matches count
- Full Subject

**URLs Found in Email:**

Table showing all URLs with:
- **Risk**: Badge showing if URL is from threat feed or calculated score
  - 🚨 THREAT FEED (100) ← From external feed
  - 🚨 CRITICAL (85-100)
  - ⚠️ HIGH (70-84)
  - ⚡ MEDIUM (50-69)
  - ✓ LOW (0-49)
- **URL**: Full or truncated URL
- **Domain**: Domain name
- **Source**: Which feed or 'email'
- **Threat Type**: Type of threat
- **Target**: Targeted brand
- **Status**: 🟢 Online / 🔴 Offline / ⚪ Unknown
- **Country**: Hosting country

**Full URL Details:**
Select any URL to see complete enrichment data:
- Basic info (URL, domain, IP, online status)
- Network info (ASN, ISP, CIDR, country, region, city, coordinates)
- SSL/TLS info (status, issuer, validity, expiry)
- Domain registration (registrar, creation date, age, name servers)
- Content (language, page title)
- Threat classification (type, target brand, tags)
- Source tracking (feed, first seen, last checked)

## Example Workflows

### 1. Check for High-Risk Emails
```
1. Open Email Monitoring tab
2. Look at "🚨 Critical Risk" metric
3. Set slider to "Minimum Risk Score: 85"
4. Review the filtered list
5. Click on an email to see which URLs triggered the high score
```

### 2. Investigate a Specific Email
```
1. Find email in the list
2. Click on it in the dropdown
3. View the Email Information section
4. See the risk score and explanation
5. Check "URLs Found in Email" table
6. Identify which URLs are from threat feeds (🚨 THREAT FEED badge)
7. Select a URL for full enrichment details
```

### 3. Monitor Threat Feed Matches
```
1. Look at "🔗 Threat Feed Matches" metric
2. Filter emails by high risk score
3. Review emails with "Threats" > 0 in the table
4. These emails contain known phishing URLs
```

### 4. Track Email Security Over Time
```
1. View the "Email Timeline" chart
2. See spikes in critical/high risk emails
3. Correlate with specific dates/campaigns
4. Identify trends
```

## Risk Score Indicators

### Email Risk Score
The email's risk score is the **MAXIMUM** of all its URLs' risk scores:

```
Email contains 3 URLs:
  - https://legitimate.com → score: 42
  - https://safe.org → score: 35
  - https://phishing.com → score: 100 (from PhishTank)

Email Risk Score = 100 (MAX of all URLs)
```

### URL Risk Score Logic

**URLs from Threat Feeds (source_feed ≠ 'email'):**
- Risk Score: **Always 100** (maximum)
- Indicator: 🚨 THREAT FEED (100)
- Why: These URLs are confirmed threats from PhishTank, URLhaus, OpenPhish

**URLs from Emails (source_feed = 'email'):**
- Risk Score: **Calculated using scoring.py**
- Components:
  1. Liveness (0-35 pts): HTTP status and online
  2. Recency (0-25 pts): Days since last seen
  3. Domain Age (0-20 pts): New domains = higher risk
  4. TLD/Platform (0-10 pts): .zip, .click = higher risk
  5. Keywords (0-10 pts): "login", "verify", "bank" = higher risk

## Color Coding

Throughout the dashboard:

| Color | Risk Level | Score Range | Icon |
|-------|------------|-------------|------|
| 🔴 Red | Critical | 85-100 | 🚨 |
| 🟠 Orange | High | 70-84 | ⚠️ |
| 🟡 Yellow | Medium | 50-69 | ⚡ |
| 🟢 Green | Low | 0-49 | ✓ |

## Integration with Email Processing

The dashboard shows real-time data from:
- `emails` table (email metadata + risk scores)
- `email_urls` table (email-URL relationships)
- `enriched_threats` table (URL details)

### Workflow:
```
1. Run: python run.py demo
   → Fetches emails continuously
   → Enriches URLs
   → Calculates risk scores

2. Open: http://localhost:8501
   → View Email Monitoring tab
   → See real-time updates every 30 seconds (auto-refresh)

3. Refresh manually
   → Click "🔄 Refresh Data" in sidebar
```

## Dashboard Features

### ✅ What You Can Do

1. **Monitor incoming emails** in real-time
2. **Identify critical threats** immediately (red badges)
3. **Drill down** into any email to see all URLs
4. **Investigate URLs** with full enrichment data
5. **Track trends** over time with timeline charts
6. **Filter by risk level** to focus on threats
7. **See which URLs** matched threat feeds
8. **Export data** for reports (if needed)

### 🔍 Quick Actions

**Find all critical emails:**
```
1. Email Monitoring tab
2. Minimum Risk Score: 85
3. Review list
```

**Check if an email contains threat feed URLs:**
```
1. Select email from dropdown
2. Look at "Threat Feed Matches" metric
3. Check URLs table for 🚨 THREAT FEED badge
```

**Get details on a suspicious URL:**
```
1. Select email
2. Find URL in "URLs Found in Email" table
3. Select URL from "Select URL for full details" dropdown
4. View complete enrichment data
```

## Auto-Refresh

The dashboard caches data for 30 seconds, then automatically refreshes:
- Email stats: 30 second cache
- Email list: 30 second cache
- Charts: 60 second cache

Manual refresh: Click **🔄 Refresh Data** button

## Statistics Tracked

The dashboard automatically calculates:
- Total emails processed
- Risk distribution (Critical/High/Medium/Low counts)
- Emails in last 24 hours
- Average risk score
- Unique URLs extracted
- Threat feed matches
- Timeline trends

## Example Use Cases

### Use Case 1: SOC Analyst Monitoring
```
Morning routine:
1. Open dashboard → Email Monitoring tab
2. Check "Critical Risk" metric
3. Review any red-flagged emails
4. Investigate threat feed matches
5. Document findings
```

### Use Case 2: Incident Response
```
Alert received about suspicious email:
1. Open Email Monitoring tab
2. Search for sender/subject in list
3. Check risk score
4. Review all URLs in email
5. Identify if URLs match known threats
6. Get full enrichment data for IOCs
```

### Use Case 3: Trend Analysis
```
Weekly review:
1. View Email Timeline chart
2. Identify spikes in risk emails
3. Check top target brands
4. Monitor new threat patterns
```

## Pro Tips

1. **Set risk filter to 70+** to focus on actionable threats
2. **Sort by Risk Score** to see most dangerous emails first
3. **Check "Threats" column** - any value > 0 means threat feed match
4. **Use URL details** to gather IOCs (IP, ASN, country, cert info)
5. **Refresh frequently** during active monitoring

## Comparison with Other Tabs

| Tab | Purpose | Data Source |
|-----|---------|-------------|
| **📧 Email Monitoring** | **Monitor incoming emails** | **emails + email_urls** |
| 📊 Threat Overview | High-level threat stats | enriched_threats |
| 📈 Analytics | Deep threat analysis | enriched_threats |
| 🔍 Data Explorer | Browse all threats | enriched_threats |
| 🔎 Search | Quick threat lookup | enriched_threats |

## Getting Data into the Dashboard

Make sure you're running email processing:

```bash
# Continuous monitoring (recommended)
python run.py demo

# Or one-time fetch + enrich
python run.py bootstrap --count 25

# Or separate steps
python run.py emails --count 25 --enrich
```

Then open the dashboard:
```bash
python run.py dashboard
```

## Next Steps

After setting up email monitoring:
1. Run `python run.py demo` in one terminal
2. Run `python run.py dashboard` in another terminal
3. Watch emails appear in real-time
4. Monitor for high-risk emails
5. Investigate threats as they arrive

The Email Monitoring tab gives you **complete visibility** into email threats with detailed risk assessment and URL analysis! 🎯

