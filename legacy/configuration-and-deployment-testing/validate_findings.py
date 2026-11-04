#!/usr/bin/env python3
"""
Enhanced validation script for configuration and deployment testing.
This script validates ffuf findings by following redirects and checking actual content.
"""

import httpx
import asyncio
from typing import List, Dict

async def validate_admin_interfaces(domain: str, paths: List[str]) -> Dict:
    """
    Validates potential admin interfaces by following redirects and analyzing content.
    """
    results = {
        "confirmed_admin_interfaces": [],
        "false_positives": [],
        "access_restricted": [],
        "validation_summary": {}
    }
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
        for path in paths:
            try:
                url = f"https://{domain}{path}"
                resp = await client.get(url)
                content = resp.text.lower()
                
                # Check for actual admin interface indicators
                admin_indicators = []
                
                if "login" in content and ("admin" in content or "dashboard" in content):
                    admin_indicators.append("admin_login_form")
                if "username" in content and "password" in content and len(content) < 50000:
                    admin_indicators.append("login_form")
                if "phpmyadmin" in content:
                    admin_indicators.append("phpmyadmin")
                if "administration" in content and "login" in content:
                    admin_indicators.append("admin_panel")
                if "wp-admin" in content or "wordpress" in content:
                    admin_indicators.append("wordpress_admin")
                if "cpanel" in content:
                    admin_indicators.append("cpanel")
                
                # Check for false positives
                false_positive_indicators = []
                
                if len(content) > 10000 and "homepage" in content:
                    false_positive_indicators.append("redirected_to_homepage")
                if "404" in content or "not found" in content:
                    false_positive_indicators.append("not_found_page")
                if resp.url != url and "index" in str(resp.url):
                    false_positive_indicators.append("redirected_to_index")
                
                # Categorize the finding
                finding = {
                    "path": path,
                    "original_url": url,
                    "final_url": str(resp.url),
                    "status_code": resp.status_code,
                    "content_length": len(content),
                    "admin_indicators": admin_indicators,
                    "false_positive_indicators": false_positive_indicators
                }
                
                if resp.status_code in [401, 403]:
                    results["access_restricted"].append({
                        **finding,
                        "classification": "access_restricted",
                        "reason": "Authentication required or forbidden"
                    })
                elif admin_indicators and not false_positive_indicators:
                    results["confirmed_admin_interfaces"].append({
                        **finding,
                        "classification": "confirmed_admin",
                        "confidence": "high"
                    })
                elif false_positive_indicators:
                    results["false_positives"].append({
                        **finding,
                        "classification": "false_positive",
                        "reason": false_positive_indicators[0]
                    })
                else:
                    results["false_positives"].append({
                        **finding,
                        "classification": "unclear",
                        "reason": "No clear admin indicators found"
                    })
                    
            except Exception as e:
                results["false_positives"].append({
                    "path": path,
                    "error": str(e),
                    "classification": "validation_failed"
                })
    
    # Generate summary
    results["validation_summary"] = {
        "total_tested": len(paths),
        "confirmed_admin": len(results["confirmed_admin_interfaces"]),
        "access_restricted": len(results["access_restricted"]),
        "false_positives": len(results["false_positives"]),
        "false_positive_rate": round((len(results["false_positives"]) / len(paths)) * 100, 1)
    }
    
    return results

async def main():
    domain = "transportasijakarta.transjakarta.co.id"
    
    # Paths that were found with status 302 in previous scan
    suspicious_paths = [
        "/admin/",
        "/admin-login/",
        "/administrator/",
        "/auth/",
        "/authentication/",
        "/backend/",
        "/cms/",
        "/cpanel/",
        "/login/",
        "/phpmyadmin/",
        "/signin/",
        "/wp-admin/",
        "/gs/admin/",
        "/processwire/",
        "/typo3/",
        "/.git/logs/"
    ]
    
    print(f"🔍 Validating {len(suspicious_paths)} potential admin interfaces for {domain}")
    print("=" * 70)
    
    results = await validate_admin_interfaces(domain, suspicious_paths)
    
    print("\n📊 VALIDATION SUMMARY:")
    print(f"Total tested: {results['validation_summary']['total_tested']}")
    print(f"Confirmed admin interfaces: {results['validation_summary']['confirmed_admin']}")
    print(f"Access restricted (401/403): {results['validation_summary']['access_restricted']}")
    print(f"False positives: {results['validation_summary']['false_positives']}")
    print(f"False positive rate: {results['validation_summary']['false_positive_rate']}%")
    
    if results["confirmed_admin_interfaces"]:
        print("\n🚨 CONFIRMED ADMIN INTERFACES:")
        for interface in results["confirmed_admin_interfaces"]:
            print(f"  ✓ {interface['path']} -> {interface['final_url']}")
            print(f"    Status: {interface['status_code']}, Indicators: {interface['admin_indicators']}")
    
    if results["access_restricted"]:
        print("\n🔒 ACCESS RESTRICTED INTERFACES:")
        for interface in results["access_restricted"]:
            print(f"  ⚠️  {interface['path']} -> Status: {interface['status_code']}")
    
    if results["false_positives"]:
        print(f"\n✅ FALSE POSITIVES ({len(results['false_positives'])}):")
        for fp in results["false_positives"][:5]:  # Show first 5
            reason = fp.get('reason', 'unknown')
            print(f"  ❌ {fp['path']} -> {reason}")
        if len(results["false_positives"]) > 5:
            print(f"  ... and {len(results['false_positives']) - 5} more")

if __name__ == "__main__":
    asyncio.run(main())
