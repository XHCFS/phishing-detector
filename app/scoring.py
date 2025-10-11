#!/usr/bin/env python3
"""
Minimal threat risk scoring module.

Calculates risk scores for URLs/emails based on technical indicators.
Score range: 0-100 (higher = more risky)

Components:
- Liveness (0-35): HTTP status and online status
- Recency (0-25): Days since last seen
- Domain Age (0-20): Days since domain creation
- TLD/Platform (0-10): TLD type and hosting platform
- Keywords (0-10): Suspicious keywords in URL

Usage:
    from app.scoring import calculate_risk_score, get_risk_level
    
    score = calculate_risk_score(
        url="https://example.com/login",
        http_status_code=200,
        online_status="yes",
        last_seen="2024-10-10",
        creation_date="2024-10-01",
        tld="com"
    )
    
    level = get_risk_level(score)  # "Critical", "High", "Medium", "Low"
"""

from datetime import datetime
from typing import Optional


def calculate_liveness_score(
    http_status_code: Optional[int] = None,
    online_status: Optional[str] = None
) -> int:
    """Calculate liveness score (0-35 points)."""
    # HTTP status codes take priority
    if http_status_code is not None:
        if http_status_code in (200, 301, 302, 307, 308):
            return 35
        elif http_status_code in (401, 403, 405, 429, 451):
            return 28
        elif 500 <= http_status_code < 600:
            return 20
        elif http_status_code in (404, 410):
            return 12
        else:
            return 10
    
    # Fall back to online status
    if online_status == "yes":
        return 20
    elif online_status == "no" or online_status is None:
        return 10
    else:
        return 10


def calculate_recency_score(last_seen: Optional[str] = None) -> int:
    """Calculate recency score (0-25 points) based on days since last seen."""
    if not last_seen:
        return 5
    
    try:
        last_seen_date = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
        days_ago = (datetime.now() - last_seen_date).days
        
        if days_ago <= 3:
            return 25
        elif days_ago <= 7:
            return 20
        elif days_ago <= 14:
            return 15
        elif days_ago <= 30:
            return 10
        else:
            return 5
    except (ValueError, AttributeError):
        return 5


def calculate_domain_age_score(creation_date: Optional[str] = None) -> int:
    """Calculate domain age score (0-20 points) based on days since creation."""
    if not creation_date:
        return 8
    
    try:
        created_date = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
        days_old = (datetime.now() - created_date).days
        
        if days_old <= 7:
            return 20
        elif days_old <= 30:
            return 15
        elif days_old <= 90:
            return 10
        else:
            return 5
    except (ValueError, AttributeError):
        return 8


def calculate_tld_platform_score(url: str, tld: Optional[str] = None) -> int:
    """Calculate TLD/platform score (0-10 points)."""
    url_lower = url.lower()
    
    # Check for ephemeral hosting platforms (we can add more)
    ephemeral_platforms = [
        '.vercel.app', '.web.app', '.github.io', '.cprapid.com',
        '.pages.dev', '.netlify.app', '.render.com', '.fly.dev'
    ]
    
    is_ephemeral = any(platform in url_lower for platform in ephemeral_platforms)
    
    if tld:
        tld_lower = tld.lower()
        
        # High-risk TLDs
        if tld_lower in ('zip', 'mov', 'top', 'cc', 'icu', 'xyz', 'click', 'info'):
            return 10  # Always max for high-risk TLDs
        
        # Common TLDs
        elif tld_lower in ('com', 'net', 'org'):
            return 8 if is_ephemeral else 5
        
        # Other TLDs
        else:
            return 10 if is_ephemeral else 7
    
    # No TLD provided, just check platform
    return 10 if is_ephemeral else 7


def calculate_keywords_score(url: str) -> int:
    """Calculate suspicious keywords score (0-10 points)."""
    url_lower = url.lower()
    
    suspicious_keywords = [
        'login', 'verify', 'secure', 'update', 'invoice', 'mfa',
        'password', 'wallet', 'bank', 'microsoft', 'office365', 'att'
    ]
    
    for keyword in suspicious_keywords:
        if keyword in url_lower:
            return 10
    
    return 0


def calculate_risk_score(
    url: str,
    http_status_code: Optional[int] = None,
    online_status: Optional[str] = None,
    last_seen: Optional[str] = None,
    creation_date: Optional[str] = None,
    tld: Optional[str] = None
) -> int:
    """
    Calculate total risk score (0-100) for a URL.
    
    Args:
        url: The URL to score
        http_status_code: HTTP response code (200, 404, etc.)
        online_status: "yes", "no", or None
        last_seen: ISO date string when URL was last seen
        creation_date: ISO date string when domain was created
        tld: Top-level domain (.com, .net, etc.)
    
    Returns:
        Risk score from 0-100 (higher = more risky)
    """
    liveness = calculate_liveness_score(http_status_code, online_status)
    recency = calculate_recency_score(last_seen)
    domain_age = calculate_domain_age_score(creation_date)
    tld_platform = calculate_tld_platform_score(url, tld)
    keywords = calculate_keywords_score(url)
    
    total_score = liveness + recency + domain_age + tld_platform + keywords
    
    # Ensure score is within 0-100 range
    return max(0, min(100, total_score))


def get_risk_level(score: int) -> str:
    """Convert numeric risk score to risk level."""
    if score >= 85:
        return "Critical"
    elif score >= 70:
        return "High"
    elif score >= 50:
        return "Medium"
    else:
        return "Low"


def get_score_breakdown(
    url: str,
    http_status_code: Optional[int] = None,
    online_status: Optional[str] = None,
    last_seen: Optional[str] = None,
    creation_date: Optional[str] = None,
    tld: Optional[str] = None
) -> dict:
    """
    Get detailed breakdown of risk score components.
    
    Returns:
        Dictionary with component scores and total
    """
    liveness = calculate_liveness_score(http_status_code, online_status)
    recency = calculate_recency_score(last_seen)
    domain_age = calculate_domain_age_score(creation_date)
    tld_platform = calculate_tld_platform_score(url, tld)
    keywords = calculate_keywords_score(url)
    total = liveness + recency + domain_age + tld_platform + keywords
    
    return {
        "liveness": liveness,
        "recency": recency,
        "domain_age": domain_age,
        "tld_platform": tld_platform,
        "keywords": keywords,
        "total": total,
        "risk_level": get_risk_level(total)
    }


# Simple test cases for validation
if __name__ == "__main__":
    # Test cases
    test_cases = [
        {
            "name": "High-risk phishing site",
            "url": "https://secure-login-microsoft.zip/verify",
            "http_status_code": 200,
            "online_status": "yes",
            "last_seen": "2024-10-11",
            "creation_date": "2024-10-10",
            "tld": "zip"
        },
        {
            "name": "Legitimate GitHub repo",
            "url": "https://github.com/user/repo",
            "http_status_code": 200,
            "online_status": "yes",
            "last_seen": "2024-10-11",
            "creation_date": "2008-01-01",
            "tld": "com"
        },
        {
            "name": "Suspicious new site",
            "url": "https://bank-update.click/login",
            "http_status_code": 200,
            "online_status": "yes",
            "last_seen": "2024-10-11",
            "creation_date": "2024-10-09",
            "tld": "click"
        }
    ]
    
    for case in test_cases:
        print(f"\n{case['name']}:")
        print(f"URL: {case['url']}")
        
        breakdown = get_score_breakdown(
            url=case['url'],
            http_status_code=case['http_status_code'],
            online_status=case['online_status'],
            last_seen=case['last_seen'],
            creation_date=case['creation_date'],
            tld=case['tld']
        )
        
        print(f"Score: {breakdown['total']}/100 ({breakdown['risk_level']})")
        print(f"  Liveness: {breakdown['liveness']}/35")
        print(f"  Recency: {breakdown['recency']}/25")
        print(f"  Domain Age: {breakdown['domain_age']}/20")
        print(f"  TLD/Platform: {breakdown['tld_platform']}/10")
        print(f"  Keywords: {breakdown['keywords']}/10")