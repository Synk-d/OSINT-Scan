import os
import pandas as pd
from typing import Dict, Any, Optional
# pyrefly: ignore [missing-import]
from google import genai

def _call_gemini(prompt: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "⚠️ **Configuration Error**: `GEMINI_API_KEY` is not set in the environment or `.env` file."
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        return response.text or "No response text generated."
    except Exception as e:
        return f"⚠️ **AI Generation Failed**: {str(e)}"


def generate_osint_brief(
    domain_val: str,
    user_val: str,
    ip_val: str,
    domain_df: pd.DataFrame,
    user_df: pd.DataFrame,
    ip_df: pd.DataFrame,
    risk_result: Dict[str, Any]
) -> str:
    """Analyzes the total OSINT data and returns a well-explained executive brief with asset relations."""
    domain_summary = ""
    if domain_val:
        domain_summary = f"- **Domain Target**: `{domain_val}`\n"
        if not domain_df.empty:
            unique_ips = [str(ip) for ip in domain_df['ip_address'].unique() if ip and str(ip) != 'None']
            sample_subdomains = domain_df['subdomain'].head(8).tolist() if 'subdomain' in domain_df.columns else []
            domain_summary += f"  - Subdomains Enumerated ({len(domain_df)} total): {', '.join(sample_subdomains)}\n"
            domain_summary += f"  - Associated IP Addresses: {', '.join(unique_ips[:10])}\n"

    user_summary = ""
    if user_val:
        user_summary = f"- **Identity Target Email**: `{user_val}`\n"
        if not user_df.empty:
            platforms = user_df['platform'].tolist() if 'platform' in user_df.columns else []
            user_summary += f"  - Platforms Found ({len(user_df)} total): {', '.join(platforms[:12])}\n"
            if 'category' in user_df.columns:
                breaches = user_df[user_df['category'] == 'Breach Intelligence']
                if not breaches.empty:
                    breach_names = breaches['display_name'].tolist() if 'display_name' in breaches.columns else []
                    user_summary += f"  - Confirmed Breach Exposures ({len(breaches)} total): {', '.join(breach_names)}\n"

    ip_summary = ""
    if ip_val or not ip_df.empty:
        target_ip = ip_val or (ip_df['ip'].iloc[0] if 'ip' in ip_df.columns and not ip_df.empty else 'Unknown')
        ip_summary = f"- **IP Infrastructure Target**: `{target_ip}`\n"
        if not ip_df.empty:
            isp = ip_df['isp'].iloc[0] if 'isp' in ip_df.columns else 'Unknown'
            country = ip_df['country'].iloc[0] if 'country' in ip_df.columns else 'Unknown'
            ip_summary += f"  - Hosting Provider / ISP: {isp} ({country})\n"
            if 'shodan_ports' in ip_df.columns and ip_df['shodan_ports'].iloc[0]:
                ip_summary += f"  - Open Ports Exposed: {ip_df['shodan_ports'].iloc[0]}\n"

    risk_summary = f"- **Calculated Threat Severity**: {risk_result['score']}/100 ({risk_result['level']})\n"
    if risk_result['breakdown']:
        risk_summary += "  - **Key Risk Drivers**:\n"
        for b in risk_result['breakdown']:
            risk_summary += f"    * {b['category']}: {b['detail']} (Severity: {b['severity']})\n"

    targets_str = ", ".join(filter(None, [f"`{user_val}`" if user_val else "", f"`{domain_val}`" if domain_val else "", f"`{ip_val}`" if ip_val else ""]))

    prompt = f"""
You are a Principal Cyber Threat Intelligence Analyst delivering a Final Executive Brief.

CRITICAL CONSTRAINTS:
- The actual target(s) being analyzed: {targets_str}.
- ALWAYS use the exact scanned target values ({targets_str}) throughout the analysis.
- NEVER use generic placeholders like `user@example.com`, `user.domain`, `user@domain`, or `example.com` under any circumstances.
- DO NOT include dictionary definitions, textbook explanations, or generic introductory fluff.
- Deliver a direct, high-impact, well-explained analysis with explicit asset correlations and relationships.
- Detail how the domain infrastructure, hosting networks, IP allocations, identity footprints, and data breach exposures correlate with one another.
- Use clear Markdown with bullet points, subheadings, and bold emphasis.

### Ingested Target Data:
{domain_summary or 'No domain data'}
{user_summary or 'No identity data'}
{ip_summary or 'No IP data'}
{risk_summary}

### Required Structure:
1. **Executive Summary**: 2 crisp sentences summarizing the operational posture and overall threat level for the specific target.
2. **Key Assets & Footprint**: Bullet points detailing specific subdomains, IP ranges, hosting infrastructure, and digital identities.
3. **Correlation & Asset Relations**: Detail explicit relationships between the targets (e.g., how domain assets map to hosting networks/IPs, or how digital identities link across platforms and breach records).
4. **Actionable Remediation**: 3 prioritized mitigation steps.
"""
    return _call_gemini(prompt)

def generate_domain_brief(domain_val: str, domain_df: pd.DataFrame, ip_df: pd.DataFrame) -> str:
    """Analyzes domain-specific OSINT data."""
    if not domain_val: return ""
    
    summary = f"Scanned Target Domain: {domain_val}\n"
    if not domain_df.empty:
        unique_ips = [str(ip) for ip in domain_df['ip_address'].unique() if ip and str(ip) != 'None']
        summary += f"- Subdomains: {len(domain_df)} found ({', '.join(domain_df['subdomain'].head(6).tolist())})\n"
        summary += f"- Resolved IPs: {', '.join(unique_ips[:8])}\n"
    if not ip_df.empty:
        isp = ip_df['isp'].iloc[0] if 'isp' in ip_df.columns else 'Unknown'
        country = ip_df['country'].iloc[0] if 'country' in ip_df.columns else 'Unknown'
        summary += f"- Hosting / ISP: {isp} ({country})\n"
        if 'shodan_ports' in ip_df.columns and ip_df['shodan_ports'].iloc[0]:
            summary += f"- Open Ports: {ip_df['shodan_ports'].iloc[0]}\n"
            
    prompt = f"""
You are a Cyber Threat Intelligence Analyst providing a Domain Overview for the scanned target domain: `{domain_val}`.

CRITICAL REQUIREMENT:
- You MUST reference `{domain_val}` explicitly as the target domain (e.g., "**Domain Overview:** `{domain_val}`").
- NEVER output generic placeholders like `example.com` or `domain.com`.

STRICT INSTRUCTIONS:
- Keep it extremely SHORT, PRECISE, and CONCISE (use 3-4 bullet points max, under 100 words total).
- NO definitions, NO generic background fluff, NO textbook explanations of what DNS/CDN/OSINT is.
- Give a direct, tactical overview of what we are working with: specific assets, hosting/ISP footprint, and exposed infrastructure for `{domain_val}`.

### Domain Data:
{summary}
"""
    return _call_gemini(prompt)

def generate_user_brief(user_val: str, user_df: pd.DataFrame) -> str:
    """Analyzes identity/email OSINT data."""
    if not user_val: return ""
    
    summary = f"Scanned Target Email: {user_val}\n"
    if not user_df.empty:
        platforms = user_df['platform'].tolist() if 'platform' in user_df.columns else []
        summary += f"- Platforms Detected ({len(user_df)}): {', '.join(platforms[:10])}\n"
        if 'category' in user_df.columns:
            breaches = user_df[user_df['category'] == 'Breach Intelligence']
            if not breaches.empty:
                breach_names = breaches['display_name'].tolist() if 'display_name' in breaches.columns else []
                summary += f"- Breach Exposures ({len(breaches)}): {', '.join(breach_names)}\n"
            
    prompt = f"""
You are a Cyber Threat Intelligence Analyst providing an Identity Overview for the scanned target email: `{user_val}`.

CRITICAL EMAIL IDENTIFIER REQUIREMENT:
- The target email being analyzed is `{user_val}`.
- You MUST reference `{user_val}` explicitly as the target email in your opening heading/overview line (e.g., "**Identity Overview:** `{user_val}`").
- NEVER use generic placeholder email addresses or domain strings like `user@example.com`, `user.domain`, `user@domain`, or `example.com` under any circumstances.

STRICT INSTRUCTIONS:
- Keep it extremely SHORT, PRECISE, and CONCISE (use 3-4 bullet points max, under 100 words total).
- NO definitions, NO generic OpSec lectures, NO textbook filler.
- Give a direct, tactical overview of what we are working with for `{user_val}`: platform presence, account footprint, and specific breach exposures.

### Identity Data:
{summary}
"""
    return _call_gemini(prompt)

