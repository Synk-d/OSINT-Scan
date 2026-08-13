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
        interaction = client.interactions.create(model='gemini-3.6-flash', input=prompt)
        return interaction.output_text
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
    """Analyzes the total OSINT data and returns a markdown-formatted executive brief."""
    # Prepare data summaries for the prompt
    domain_summary = f"Domain Target: {domain_val}\n" if domain_val else ""
    if not domain_df.empty:
        domain_summary += f"Found {len(domain_df)} subdomains. IPs: {', '.join(domain_df['ip_address'].unique())}\n"

    user_summary = f"Email/Identity Target: {user_val}\n" if user_val else ""
    if not user_df.empty:
        platforms = user_df['platform'].tolist()
        user_summary += f"Found profiles/records on {len(user_df)} platforms: {', '.join(platforms)}\n"
        breaches = user_df[user_df['category'] == 'Breach Intelligence']
        if not breaches.empty:
            user_summary += f"Breach Exposure Detected: {breaches['display_name'].tolist()}\n"

    ip_summary = f"IP Target: {ip_val}\n" if ip_val else ""
    if not ip_df.empty:
        ip_summary += f"ISP: {ip_df['isp'].iloc[0] if 'isp' in ip_df.columns else 'Unknown'}, Location: {ip_df['country'].iloc[0] if 'country' in ip_df.columns else 'Unknown'}\n"
        if 'shodan_ports' in ip_df.columns and ip_df['shodan_ports'].iloc[0]:
            ip_summary += f"Open Ports: {ip_df['shodan_ports'].iloc[0]}\n"

    risk_summary = f"Risk Score: {risk_result['score']}/100 ({risk_result['level']})\n"
    if risk_result['breakdown']:
        risk_summary += "Key Risks:\n"
        for b in risk_result['breakdown']:
            risk_summary += f"- {b['category']}: {b['detail']} ({b['severity']})\n"

    prompt = f"""
You are an expert Cyber Intelligence (OSINT) Analyst. I have conducted an OSINT sweep and need an Executive Brief.

Please analyze the following data and provide a concise, highly professional executive summary. 
Explain the overall meaning, the gist of the findings, and any potential security risks or operational impacts.
Format the output in clean Markdown (use headings, bullet points, and bold text for emphasis).
Do not just repeat the data; synthesize what this means for a security team or the target.

### OSINT Sweep Data:

{domain_summary}
{user_summary}
{ip_summary}
{risk_summary}

### Required Structure:
1. **Executive Summary**: 2-3 sentences summarizing the overall posture.
2. **Key Findings**: Bullet points of the most critical discoveries.
3. **Risk & Threat Analysis**: What do these findings mean from a security perspective? (e.g. breach exposure, open ports, identity sprawl).
4. **Actionable Recommendations**: 2-3 steps the target or security team should take to mitigate risks.
"""
    return _call_gemini(prompt)

def generate_domain_brief(domain_val: str, domain_df: pd.DataFrame, ip_df: pd.DataFrame) -> str:
    """Analyzes domain-specific OSINT data."""
    if not domain_val: return ""
    summary = f"Domain Target: {domain_val}\n"
    if not domain_df.empty:
        summary += f"Found {len(domain_df)} subdomains. IPs: {', '.join(domain_df['ip_address'].unique())}\n"
    if not ip_df.empty:
        summary += f"ISP: {ip_df['isp'].iloc[0] if 'isp' in ip_df.columns else 'Unknown'}, Location: {ip_df['country'].iloc[0] if 'country' in ip_df.columns else 'Unknown'}\n"
        if 'shodan_ports' in ip_df.columns and ip_df['shodan_ports'].iloc[0]:
            summary += f"Open Ports: {ip_df['shodan_ports'].iloc[0]}\n"
            
    prompt = f"""
You are an expert Cyber Intelligence (OSINT) Analyst evaluating a domain infrastructure.
Analyze this domain's footprint and write a 2-3 paragraph summary of the findings, explaining the risk context of exposed ports, subdomains, or hosting providers.
Do not use headings, just provide a clear, concise professional analysis in Markdown.

### Domain Sweep Data:
{summary}
"""
    return _call_gemini(prompt)

def generate_user_brief(user_val: str, user_df: pd.DataFrame) -> str:
    """Analyzes identity/email OSINT data."""
    if not user_val: return ""
    summary = f"Identity Target: {user_val}\n"
    if not user_df.empty:
        platforms = user_df['platform'].tolist()
        summary += f"Found profiles/records on {len(user_df)} platforms: {', '.join(platforms)}\n"
        breaches = user_df[user_df['category'] == 'Breach Intelligence']
        if not breaches.empty:
            summary += f"Breach Exposure Detected: {breaches['display_name'].tolist()}\n"
            
    prompt = f"""
You are an expert Cyber Intelligence (OSINT) Analyst evaluating a digital identity.
Analyze this email/username footprint and write a 2-3 paragraph summary of the findings. Explain the operational security (OpSec) risks of their digital footprint across the platforms found, and detail the severity of any data breaches they are involved in.
Do not use headings, just provide a clear, concise professional analysis in Markdown.

### Identity Sweep Data:
{summary}
"""
    return _call_gemini(prompt)
