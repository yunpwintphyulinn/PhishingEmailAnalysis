# Phishing Triage Report

## 1. Executive Summary
A suspicious email impersonating a commercial purchase receipt contained a link directing the recipient to an executable hosted on a raw IP address. Header analysis showed the message was transmitted through authenticated infrastructure associated with the sender domain, while its mass-distribution characteristics and malicious delivery link indicated phishing activity. Threat-intelligence analysis identified malicious detections for the linked resource, although later dynamic retrieval did not recover the original executable payload. The email was therefore classified as malicious with high confidence, while sender-account compromise remained an analyst assessment rather than a confirmed fact.

## 2. Sample Overview
- **Subject**: COMMERCIAL PURCHASE RECEIPT ONLINE 27 NOV
- **Sender**: ERIKA JOHANA LOPEZ VALIENTE <erikajohana.lopez@uptc.edu.co>
- **Date received**: Thu, 9 Dec 2022 09:58:26 +0100
- **Contain one link** : hxxp://107.175.247.199/loader/install.exe

## 3. Header Analysis
- **From**: erikajohana.lopez@uptc.edu.co (legitimate university domain, not spoofed)
- **Return-Path** matches From — no mismatch
- **SPF**: pass (mail genuinely sent via Google Workspace infrastructure for uptc.edu.co)
- **DKIM**: none — message not signed, unusual for a properly configured account
- **DMARC**: pass by default — uptc.edu.co has no DMARC policy published, so this is not a meaningful pass
- Message-ID domain (mail.gmail.com) confirms webmail origin, consistent with SPF findings
- Recipient field "undisclosed-recipients" indicates mass Bcc distribution, typical of malspam campaigns
- **Assessment**: sender account is likely COMPROMISED rather than spoofed — legitimate 
  infrastructure, no domain mismatch, but used to distribute malicious content
  
## 4. Link Analysis
- **URL**: http://107.175.247.199/loader/install.exe
- **VirusTotal detection**: 12/93 security vendors flagged as malicious
- **Notable characteristics**: raw IP address (no domain), .exe payload disguised 
  as an invoice/document link in email body
- **Assessment**: confirmed malicious — likely loader/dropper based on filename pattern

## 5. Payload/Sandbox Analysis
- **Sandbox**: Hybrid Analysis
- **Submission**: hxxp://107.175.247.199/loader/install.exe
- **Result**: "No specific threat" / marked clean
- **Retrieved file size**: 65 bytes — far too small to be the actual executable 
  payload, indicating the hosting infrastructure is no longer serving the 
  real malicious file
- **AV vendors on Hybrid Analysis** (urlscan.io, CleanDNS, Criminal IP, Vipre): 
  no detections — consistent with dead infrastructure, not a benign verdict
- **Contrast with VirusTotal**: 12/93 vendors flag this URL/file as malicious 
  (see Section 4) — this detection was recorded while the infrastructure 
  was still active
- **Assessment**: sample is confirmed malicious based on VirusTotal detections 
  and file-naming/delivery pattern (fake invoice lure → raw IP → .exe); 
  The hosting endpoint no longer returned the expected payload at the time of analysis. (sample dates to Dec 2022)

## 6. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| Sender account — suspected compromise | erikajohana.lopez@uptc.edu.co | Legitimate university account, likely compromised (not spoofed) |
| Sending infrastructure | mail-wr1-f65.google.com (209.85.221.65) | Google Workspace infra used by uptc.edu.co — legitimate, abused |
| Malicious URL | hxxp://107.175.247.199/loader/install.exe | Payload delivery link disguised as invoice document |
| Hosting IP | 107.175.247.199 | Raw IP, no domain — hosts the malicious executable |
| Payload filename | install.exe | Delivered via "loader" path, consistent with malware dropper naming |
| Email subject | COMMERCIAL PURCHASE RECEIPT ONLINE 27 NOV | Fake invoice/receipt lure |
| Distribution method | undisclosed-recipients (Bcc) | Mass malspam pattern |
| VirusTotal detection | 12/93 vendors flagged malicious | Confirms malicious classification |

## 7. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Email body contains a disguised link ("VIEW INVOICE DOCUMENT HERE") pointing to a malicious payload URL |
| Valid Accounts | T1078 | Sender is a legitimate, authenticated uptc.edu.co / Google Workspace account with passing SPF — consistent with account compromise rather than domain spoofing |
| User Execution: Malicious File | T1204.002 | Victim is lured into clicking the link and would need to manually run install.exe to trigger infection |
| Masquerading | T1036 | Executable disguised as an "invoice document"; delivered via a raw IP rather than a branded domain to evade quick visual detection |

## 8. Verdict

**Malicious — Confidence: High**

Despite inconclusive sandbox detonation (due to dead hosting infrastructure), 
the verdict is supported by:
- VirusTotal detection ratio of 12/93
- Payload delivery pattern consistent with known malspam TTPs (fake invoice 
  lure, raw IP hosting, .exe disguised as document)
- Mass Bcc distribution pattern
- Sender account behavior inconsistent with legitimate use (unsolicited 
  "purchase receipt" sent to undisclosed recipients)

The absence of dynamic sandbox evidence is attributed to sample age 
(Dec 2022) and infrastructure takedown, not to benign content.

## 9. Recommended Actions

1. Block the malicious URL and hosting IP (107.175.247.199) at the email 
   gateway / firewall level.
2. Quarantine/remove all copies of this email from mailboxes across the 
   organization (retroactive search by subject line and sender).
3. Notify the owner of erikajohana.lopez@uptc.edu.co (or their IT team) — 
   the account shows signs of compromise and should have its password 
   reset and MFA enforced.
4. Alert any recipients who may have clicked the link or attempted to 
   run the file to check their systems for signs of compromise.
5. Add the IOCs from Section 6 to the organization's threat intelligence 
   feed / SIEM watchlist.
6. Consider enabling DMARC enforcement recommendations for domains lacking 
   a policy (relevant if this were an internal domain — informational 
   note for awareness).
   
## 10. Tool Used
- VirusTotal
- Hybrid Analysis
- CyberChef

