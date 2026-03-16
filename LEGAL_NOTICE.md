# Legal Notice and Responsible Use Policy

## Authorised Use Only

This software ("HARIS") is designed and intended **exclusively** for authorised security testing and assessment purposes. By using this software, you agree to the following terms:

1. **Authorisation Required**: You must have **explicit, written permission** from the system owner before scanning or testing any target. This typically takes the form of a signed Rules of Engagement (RoE) or penetration testing agreement.

2. **Scope Compliance**: All testing must remain within the authorised scope. The software includes scope-enforcement features (allowed domains, excluded paths, rate limits) that **must** be configured correctly to match your engagement agreement.

3. **No Malicious Use**: This software must not be used for:
   - Unauthorised access to systems
   - Data exfiltration or theft
   - Denial of service attacks
   - Any activity that violates applicable laws or regulations

4. **Data Handling**: The software is designed to **demonstrate** vulnerabilities, not to harvest or store sensitive data. Any data collected during testing must be handled in accordance with applicable data protection laws (e.g., GDPR, CCPA) and your engagement agreement.

5. **Legal Compliance**: Users are responsible for ensuring their use of this software complies with all applicable local, national, and international laws and regulations, including but not limited to:
   - Computer Fraud and Abuse Act (CFAA) - United States
   - Computer Misuse Act 1990 - United Kingdom
   - Council of Europe Convention on Cybercrime (Budapest Convention)
   - Equivalent legislation in your jurisdiction

## Liability Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHORS AND CONTRIBUTORS ARE NOT LIABLE FOR ANY DAMAGES OR LEGAL CONSEQUENCES ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.

The authors do not endorse, encourage, or condone any illegal activity. Users assume full responsibility for their actions when using this software.

## Recommended Practices

- Always obtain **written authorisation** before any testing
- Define and document the **scope** of testing clearly
- Configure **rate limits** and **request caps** to avoid service disruption
- Use **test payloads** that demonstrate vulnerabilities without causing harm
- **Report findings** responsibly to system owners
- **Delete test data** after the engagement is complete
- Maintain an **audit log** of all testing activities

## Third-Party Scanner Licenses

HARIS integrates with several open source security scanners (Nuclei, Nikto, Wapiti, Nmap, SSLyze). Each scanner is invoked as an independent external subprocess and retains its own license. Users are responsible for:

- Installing each scanner tool separately
- Complying with each tool's license terms
- Obtaining an Nmap OEM license if using Nmap in a commercial product

For full details, see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
