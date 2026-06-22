# v15.0.0 New-Challenge Categorization — REVIEW BEFORE LOCK

Total new challenges: 45 | Automatable: 23

| Challenge | Category | Auto | WSTG | Reason |
|---|---|---|---|---|
| Extra Language | Broken Anti Automation | N | - | anti-automation language-file puzzle |
| Reset Morty's Password | Broken Anti Automation | N | - | CAPTCHA + obfuscated security answer |
| Bjoern's Favorite Pet | Broken Authentication | N | - | security-question OSINT about a real person |
| GDPR Data Erasure | Broken Authentication | Y | WSTG-INPV-05 | SQLi to access soft-deleted account — existing INPV-05 |
| Login Bjoern | Broken Authentication | N | - | requires knowing real account email + unchanged password |
| Reset Bender's Password | Broken Authentication | N | - | security-question OSINT |
| Reset Bjoern's Password | Broken Authentication | N | - | security-question OSINT |
| Imaginary Challenge | Cryptographic Issues | N | - | meta joke — non-existent challenge #999 |
| Nested Easter Egg | Cryptographic Issues | N | - | manual cryptanalysis / forensics |
| Premium Paywall | Cryptographic Issues | N | - | multi-step crypto puzzle / source analysis |
| Weird Crypto | Cryptographic Issues | Y | WSTG-CRYP-04 | detect insecure crypto algorithm in use — CRYP-04 |
| Empty User Registration | Improper Input Validation | Y | WSTG-IDNT-02 | missing input validation on registration — IDNT-02 |
| Missing Encoding | Improper Input Validation | Y | WSTG-INPV-01 | encoded path to served media file — INPV/CONF |
| Ephemeral Accountant | Injection | Y | WSTG-INPV-05 | SQLi login as non-existent user — INPV-05 |
| User Credentials | Injection | Y | WSTG-INPV-05 | UNION SQLi credential dump — INPV-05 |
| Blocked RCE DoS | Insecure Deserialization | N | - | destructive DoS — system must not run DoS against target |
| Successful RCE DoS | Insecure Deserialization | N | - | destructive DoS — system must not run DoS against target |
| Bully Chatbot | Miscellaneous | N | - | chatbot interaction |
| Mass Dispel | Miscellaneous | N | - | UI-only: close multiple notifications |
| Privacy Policy | Miscellaneous | N | - | UI-only: read the privacy policy page |
| Login Support Team | Security Misconfiguration | N | - | requires recovering hardcoded original credentials (OSINT-like) |
| Blockchain Hype | Security through Obscurity | N | - | external announcement OSINT |
| Privacy Policy Inspection | Security through Obscurity | N | - | client-side obscurity puzzle in policy page |
| Steganography | Security through Obscurity | N | - | image steganography forensics |
| GDPR Data Theft | Sensitive Data Exposure | Y | WSTG-ATHZ-04 | broken object-level authorization on data export |
| Leaked Access Logs | Sensitive Data Exposure | N | - | keyword rule: 'dumpster dive' |
| Leaked Unsafe Product | Sensitive Data Exposure | Y | WSTG-INPV-05 | SQLi to surface removed product — existing INPV-05 |
| Login Amy | Sensitive Data Exposure | Y | WSTG-ATHN-07 | weak/guessable credentials — ATHN-07 |
| Meta Geo Stalking | Sensitive Data Exposure | Y | WSTG-CONF-04 | EXIF GPS metadata on served image — covered by new EXIF tool |
| Reset Uvogin's Password | Sensitive Data Exposure | N | - | security-question OSINT |
| Retrieve Blueprint | Sensitive Data Exposure | Y | WSTG-CONF-04 | forced browsing to unreferenced file — CONF-04 |
| Visual Geo Stalking | Sensitive Data Exposure | N | - | needs visual landmark recognition, not metadata |
| Arbitrary File Write | Vulnerable Components | Y | WSTG-BUSL-08 | zip-slip / file upload — existing BUSL-08 detection |
| Frontend Typosquatting | Vulnerable Components | Y | WSTG-CONF-01 | package-name edit-distance — covered by new SCA tool |
| Kill Chatbot | Vulnerable Components | N | - | chatbot manipulation |
| Legacy Typosquatting | Vulnerable Components | Y | WSTG-CONF-01 | package-name edit-distance — covered by new SCA tool |
| Local File Read | Vulnerable Components | Y | WSTG-BUSL-09 | path traversal — existing BUSL-09 detection |
| Unsigned JWT | Vulnerable Components | Y | WSTG-CRYP-04 | JWT alg=none — existing CRYP-04 detection |
| API-only XSS | XSS | Y | WSTG-INPV-01 | persisted XSS via API — INPV-01 |
| Client-side XSS Protection | XSS | Y | WSTG-CLNT-01 | XSS bypassing client filter — CLNT-01 |
| HTTP-Header XSS | XSS | Y | WSTG-INPV-01 | persisted XSS via HTTP header — INPV-01 |
| Reflected XSS | XSS | Y | WSTG-CLNT-01 | reflected XSS — CLNT-01 |
| Server-side XSS Protection | XSS | Y | WSTG-INPV-01 | persisted XSS bypassing server filter — INPV-01 |
| Video XSS | XSS | Y | WSTG-INPV-01 | persisted XSS via subtitle file — INPV-01 |
| XXE DoS | XXE | Y | WSTG-INPV-07 | XXE — existing INPV-07 detection |