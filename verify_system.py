#!/usr/bin/env python3
"""
RAJDOLL System Verification Script
Comprehensive checks for all components
"""

import sys
import time
import requests
import subprocess
from typing import Dict, Any

class SystemVerifier:
    def __init__(self):
        self.results = {}
        self.api_base = "http://localhost:8000"

    def print_header(self, title: str):
        print("\n" + "=" * 60)
        print(f"  {title}")
        print("=" * 60)

    def check_docker_services(self) -> bool:
        """Check if all Docker services are running"""
        self.print_header("🐳 Docker Services")

        try:
            result = subprocess.run(
                ["docker", "compose", "ps", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                print("❌ Docker Compose not accessible")
                return False

            # Count running services
            import json
            services = [json.loads(line) for line in result.stdout.strip().split('\n') if line]
            running = sum(1 for s in services if s.get('State') == 'running')

            print(f"✅ Docker services: {running}/{len(services)} running")

            # Check critical services
            critical = ['api', 'worker', 'db', 'redis']
            for service in critical:
                service_running = any(
                    s.get('Service') == service and s.get('State') == 'running'
                    for s in services
                )
                status = "✅" if service_running else "❌"
                print(f"   {status} {service}")

            self.results['docker'] = running == len(services)
            return self.results['docker']

        except Exception as e:
            print(f"❌ Docker check failed: {e}")
            self.results['docker'] = False
            return False

    def check_lm_studio(self) -> bool:
        """Check LM Studio connection"""
        self.print_header("🧠 LM Studio Server")

        try:
            response = requests.get(
                "http://172.16.0.2:1234/v1/models",
                timeout=5
            )

            if response.status_code == 200:
                models = response.json()
                model_count = len(models.get('data', []))

                if model_count > 0:
                    print(f"✅ LM Studio responding ({model_count} models loaded)")
                    for model in models['data']:
                        print(f"   📦 {model.get('id')}")
                    self.results['lm_studio'] = True
                    return True
                else:
                    print("⚠️  LM Studio running but no models loaded")
                    print("   Action: Load qwen2.5-7b model in LM Studio")
                    self.results['lm_studio'] = False
                    return False
            else:
                print(f"❌ LM Studio returned {response.status_code}")
                self.results['lm_studio'] = False
                return False

        except requests.exceptions.ConnectionError:
            print("❌ Cannot connect to LM Studio (http://172.16.0.2:1234)")
            print("   Action: Start LM Studio server")
            self.results['lm_studio'] = False
            return False
        except Exception as e:
            print(f"❌ LM Studio check failed: {e}")
            self.results['lm_studio'] = False
            return False

    def check_api_health(self) -> bool:
        """Check RAJDOLL API health"""
        self.print_header("🚀 RAJDOLL API")

        try:
            response = requests.get(f"{self.api_base}/api/scans", timeout=5)

            if response.status_code == 200:
                scans = response.json()
                print(f"✅ API responding (found {len(scans)} scans)")
                self.results['api'] = True
                return True
            else:
                print(f"❌ API returned {response.status_code}")
                self.results['api'] = False
                return False

        except Exception as e:
            print(f"❌ API check failed: {e}")
            self.results['api'] = False
            return False

    def check_llm_planning_config(self) -> bool:
        """Check .env LLM configuration"""
        self.print_header("⚙️  LLM Planning Configuration")

        try:
            with open('.env', 'r') as f:
                env_content = f.read()

            checks = {
                'LLM_PROVIDER': 'openai',
                'LLM_BASE_URL': 'http://host.docker.internal:1234/v1',
                'DISABLE_LLM_PLANNING': 'false'
            }

            all_ok = True
            for key, expected in checks.items():
                if f'{key}={expected}' in env_content or f'{key}="{expected}"' in env_content:
                    print(f"✅ {key}={expected}")
                elif key in env_content and not env_content.split(key)[1].split('\n')[0].startswith('#'):
                    actual = env_content.split(f'{key}=')[1].split('\n')[0].strip().strip('"')
                    print(f"⚠️  {key}={actual} (expected: {expected})")
                    if key == 'DISABLE_LLM_PLANNING':
                        all_ok = False
                else:
                    print(f"❌ {key} not found or commented")
                    all_ok = False

            self.results['llm_config'] = all_ok
            return all_ok

        except Exception as e:
            print(f"❌ Config check failed: {e}")
            self.results['llm_config'] = False
            return False

    def run_quick_scan_test(self) -> bool:
        """Start a quick test scan and monitor initial LLM activity"""
        self.print_header("🧪 Quick LLM Planning Test")

        print("Starting test scan on Juice Shop...")
        try:
            # Start scan
            response = requests.post(
                f"{self.api_base}/api/scans",
                json={"target": "http://juice-shop:3000"},
                timeout=10
            )

            if response.status_code != 200:
                print(f"❌ Failed to start scan: {response.status_code}")
                self.results['scan_test'] = False
                return False

            job_id = response.json().get('job_id')
            print(f"✅ Scan started (Job ID: {job_id})")

            # Wait for initial logs
            print("Waiting 15s for LLM planning to initialize...")
            time.sleep(15)

            # Check logs for LLM activity
            try:
                result = subprocess.run(
                    ["docker", "compose", "logs", "worker", "--tail", "100"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                logs = result.stdout

                # Look for LLM planning indicators
                indicators = {
                    'SimpleLLMClient initialized': '🧠 LLM Client initialized',
                    'Using LLM arguments': '✅ LLM arguments being used',
                    'final_args': '✅ Arguments merged',
                    'OPENAI_API_KEY not set': '❌ LLM planning failed (API key issue)'
                }

                found = {}
                for indicator, message in indicators.items():
                    if indicator in logs:
                        found[indicator] = True
                        if '❌' in message:
                            print(f"   {message}")
                        else:
                            print(f"   {message}")

                # Check if LLM planning is working
                llm_working = (
                    'SimpleLLMClient initialized' in found or
                    'Using LLM arguments' in found
                ) and 'OPENAI_API_KEY not set' not in found

                if llm_working:
                    print("\n✅ LLM planning appears to be working!")
                    self.results['scan_test'] = True
                    return True
                else:
                    print("\n⚠️  LLM planning not detected in logs")
                    print("   This may be normal if scan just started")
                    print("   Check logs: docker compose logs worker -f")
                    self.results['scan_test'] = False
                    return False

            except Exception as e:
                print(f"⚠️  Could not check logs: {e}")
                self.results['scan_test'] = False
                return False

        except Exception as e:
            print(f"❌ Scan test failed: {e}")
            self.results['scan_test'] = False
            return False

    def print_summary(self):
        """Print verification summary"""
        self.print_header("📊 Verification Summary")

        total = len(self.results)
        passed = sum(1 for v in self.results.values() if v)

        print(f"\nResults: {passed}/{total} checks passed\n")

        for check, result in self.results.items():
            status = "✅" if result else "❌"
            print(f"  {status} {check.replace('_', ' ').title()}")

        print("\n" + "=" * 60)

        if passed == total:
            print("🎉 All systems operational!")
            print("\nReady for full testing:")
            print("  • Run scan: curl -X POST http://localhost:8000/api/scans -H 'Content-Type: application/json' -d '{\"target\": \"http://juice-shop:3000\"}'")
            print("  • Monitor: python test_websocket.py --job-id <ID>")
            return True
        else:
            print("⚠️  Some checks failed. Review errors above.")
            return False

def main():
    verifier = SystemVerifier()

    print("=" * 60)
    print("  🔍 RAJDOLL System Verification")
    print("=" * 60)

    # Run all checks
    verifier.check_docker_services()
    verifier.check_lm_studio()
    verifier.check_api_health()
    verifier.check_llm_planning_config()

    # Optional: Run scan test (commented out by default - takes 15s)
    # Uncomment to include scan test:
    # verifier.run_quick_scan_test()

    # Print summary
    success = verifier.print_summary()

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
