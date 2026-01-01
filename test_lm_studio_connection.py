#!/usr/bin/env python3
"""
LM Studio Connection Test
Verifies LM Studio server is accessible from Docker containers
"""

import sys
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def test_connection(base_url: str = "http://172.16.0.2:1234"):
    """Test connection to LM Studio server"""
    print("=" * 60)
    print("🧠 LM Studio Connection Test")
    print("=" * 60)
    print(f"Testing: {base_url}")
    print()

    # Test 1: Server health
    try:
        response = requests.get(f"{base_url}/v1/models", timeout=5)
        if response.status_code == 200:
            print("✅ Server is responding")
            models = response.json()

            if 'data' in models and len(models['data']) > 0:
                print(f"✅ Loaded models: {len(models['data'])}")
                for model in models['data']:
                    model_id = model.get('id', 'unknown')
                    print(f"   📦 {model_id}")
            else:
                print("⚠️  No models loaded in LM Studio")
                print("   Action: Load a model in LM Studio (qwen2.5-7b-instruct recommended)")
                return False
        else:
            print(f"❌ Server returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to LM Studio")
        print("   Action: Start LM Studio and load a model")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

    print()

    # Test 2: Simple completion
    print("Testing LLM completion...")
    try:
        response = requests.post(
            f"{base_url}/v1/chat/completions",
            json={
                "model": models['data'][0]['id'],
                "messages": [
                    {"role": "user", "content": "Say 'LM Studio is working!' in one sentence."}
                ],
                "max_tokens": 50,
                "temperature": 0.7
            },
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            message = result['choices'][0]['message']['content']
            print(f"✅ LLM Response: {message.strip()}")
        else:
            print(f"❌ Completion failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Completion error: {e}")
        return False

    print()
    print("=" * 60)
    print("✅ LM Studio is ready for RAJDOLL!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Ensure .env has:")
    print("   LLM_BASE_URL=http://host.docker.internal:1234/v1")
    print("2. Restart Docker: docker compose restart worker api")
    print("3. Run test scan: /run-scan http://juice-shop:3000")
    print()

    return True

if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)
