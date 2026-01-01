#!/usr/bin/env python3
"""
WebSocket Testing Script for RAJDOLL Multi-Agent System
Tests real-time monitoring and event streaming
"""

import asyncio
import websockets
import json
import sys
from datetime import datetime
from typing import Dict, Any

class WebSocketTester:
    def __init__(self, host: str = "localhost", port: int = 8000):
        self.host = host
        self.port = port
        self.events_received = []

    async def test_connection(self, job_id: int = 1):
        """Test WebSocket connection and event streaming"""
        uri = f"ws://{self.host}:{self.port}/ws/{job_id}"

        print(f"🔗 Connecting to WebSocket: {uri}")

        try:
            async with websockets.connect(uri) as websocket:
                print("✅ WebSocket connected successfully!")
                print("📡 Listening for events (Press Ctrl+C to stop)...\n")

                # Listen for events
                async for message in websocket:
                    await self.handle_message(message)

        except (websockets.exceptions.ConnectionClosed, ConnectionRefusedError):
            print(f"❌ Connection refused. Is the server running on {self.host}:{self.port}?")
            print("   Try: docker compose up -d")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\n⏹️  Stopped by user")
            self.print_summary()
        except Exception as e:
            print(f"❌ WebSocket error: {e}")
            sys.exit(1)

    async def handle_message(self, message: str):
        """Process received WebSocket message"""
        try:
            data = json.loads(message)
            self.events_received.append(data)

            # Extract event details
            event_type = data.get("type", "unknown")
            timestamp = datetime.now().strftime("%H:%M:%S")

            # Color-coded output based on event type
            if event_type == "agent_start":
                agent = data.get("agent_name", "Unknown")
                print(f"🚀 [{timestamp}] Agent Started: {agent}")

            elif event_type == "agent_complete":
                agent = data.get("agent_name", "Unknown")
                duration = data.get("duration", 0)
                print(f"✅ [{timestamp}] Agent Completed: {agent} ({duration:.1f}s)")

            elif event_type == "finding":
                severity = data.get("severity", "info").upper()
                title = data.get("title", "Unknown")
                severity_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🔵",
                    "INFO": "⚪"
                }.get(severity, "⚪")
                print(f"{severity_icon} [{timestamp}] Finding: [{severity}] {title}")

            elif event_type == "tool_execution":
                tool = data.get("tool_name", "Unknown")
                status = data.get("status", "unknown")
                print(f"🔧 [{timestamp}] Tool: {tool} - {status}")

            elif event_type == "error":
                error = data.get("message", "Unknown error")
                print(f"❌ [{timestamp}] Error: {error}")

            elif event_type == "log":
                level = data.get("level", "info").upper()
                message_text = data.get("message", "")[:100]
                if level in ["ERROR", "WARNING"]:
                    print(f"⚠️  [{timestamp}] {level}: {message_text}")

            else:
                # Generic message
                msg = data.get("message", str(data)[:100])
                print(f"📨 [{timestamp}] {event_type}: {msg}")

        except json.JSONDecodeError:
            print(f"⚠️  Invalid JSON: {message[:100]}")
        except Exception as e:
            print(f"⚠️  Error processing message: {e}")

    def print_summary(self):
        """Print summary of received events"""
        print("\n" + "="*60)
        print("📊 WebSocket Test Summary")
        print("="*60)
        print(f"Total events received: {len(self.events_received)}")

        # Count by event type
        event_counts = {}
        for event in self.events_received:
            event_type = event.get("type", "unknown")
            event_counts[event_type] = event_counts.get(event_type, 0) + 1

        print("\nEvents by type:")
        for event_type, count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {event_type:20s}: {count:4d}")

        # Count findings by severity
        findings = [e for e in self.events_received if e.get("type") == "finding"]
        if findings:
            print(f"\nFindings by severity:")
            severity_counts = {}
            for finding in findings:
                severity = finding.get("severity", "info").upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if severity in severity_counts:
                    print(f"  {severity:10s}: {severity_counts[severity]:4d}")

        print("="*60)

async def test_with_timeout(tester: WebSocketTester, job_id: int, timeout: int = 60):
    """Test WebSocket with timeout"""
    try:
        await asyncio.wait_for(tester.test_connection(job_id), timeout=timeout)
    except asyncio.TimeoutError:
        print(f"\n⏱️  Test completed after {timeout}s timeout")
        tester.print_summary()

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Test RAJDOLL WebSocket connection")
    parser.add_argument("--host", default="localhost", help="Server host (default: localhost)")
    parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")
    parser.add_argument("--job-id", type=int, default=1, help="Job ID to monitor (default: 1)")
    parser.add_argument("--timeout", type=int, help="Timeout in seconds (default: unlimited)")

    args = parser.parse_args()

    tester = WebSocketTester(host=args.host, port=args.port)

    print("="*60)
    print("🧪 RAJDOLL WebSocket Tester")
    print("="*60)
    print(f"Host: {args.host}:{args.port}")
    print(f"Job ID: {args.job_id}")
    print(f"Timeout: {args.timeout}s" if args.timeout else "Timeout: unlimited")
    print("="*60 + "\n")

    try:
        if args.timeout:
            asyncio.run(test_with_timeout(tester, args.job_id, args.timeout))
        else:
            asyncio.run(tester.test_connection(args.job_id))
    except KeyboardInterrupt:
        print("\n\n⏹️  Interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main()
