#!/usr/bin/env python3
"""
Super simple starter script - just the essentials.
"""
import sys
import subprocess
from pathlib import Path

def print_menu():
    """Print simple menu."""
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                  🔒 PHISHING EMAIL DETECTOR                        ║
╚═══════════════════════════════════════════════════════════════════╝

Choose an option:

  [1] 🎬 Demo Mode (Easiest - does everything)
  [2] 🔐 Authenticate Gmail
  [3] 📧 Analyze Emails (one-shot)
  [4] 📊 Open Dashboard
  [5] ❓ Help & Docs
  [Q] Quit

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)

def run_command(cmd):
    """Run a command."""
    print(f"\n▶ Running: {' '.join(cmd)}\n")
    print("─" * 70)
    result = subprocess.run(cmd)
    return result.returncode

def main():
    while True:
        print_menu()
        choice = input("Enter choice: ").strip().lower()
        
        if choice == '1':
            print("\n🎬 Starting Demo Mode...")
            print("\n💡 This will:")
            print("   • Auto-setup database (if needed)")
            print("   • Authenticate Gmail (if needed)")
            print("   • Fetch 5 emails")
            print("   • Analyze for threats")
            print("   • Then stop (use 'python run.py demo' for continuous)")
            print()
            input("Press Enter to continue, or Ctrl+C to cancel...")
            run_command(["python", "run.py", "demo", "--once"])
            print("\n✅ Demo complete! Run option [4] to view results in dashboard.")
            input("\nPress Enter to continue...")
            
        elif choice == '2':
            print("\n🔐 Gmail Authentication...")
            print("   A browser will open for Google OAuth.")
            print("   You only need to do this once.")
            print()
            input("Press Enter to continue, or Ctrl+C to cancel...")
            run_command(["python", "run.py", "auth"])
            input("\nPress Enter to continue...")
            
        elif choice == '3':
            print("\n📧 Analyze Emails...")
            count = input("   How many emails to fetch? [default: 10]: ").strip()
            count = count if count else "10"
            run_command(["python", "run.py", "bootstrap", "--count", count])
            print("\n✅ Analysis complete! Run option [4] to view results.")
            input("\nPress Enter to continue...")
            
        elif choice == '4':
            print("\n📊 Opening Dashboard...")
            print("   Dashboard will open at: http://localhost:8501")
            print("   Press Ctrl+C to stop the dashboard.")
            print()
            input("Press Enter to continue, or Ctrl+C to cancel...")
            run_command(["python", "run.py", "dashboard"])
            
        elif choice == '5':
            print("""
╔═══════════════════════════════════════════════════════════════════╗
║                           📚 HELP                                  ║
╚═══════════════════════════════════════════════════════════════════╝

🎯 SIMPLE COMMANDS:

  python run.py demo --once    → Test everything once
  python run.py demo           → Continuous monitoring
  python run.py auth           → Authenticate Gmail
  python run.py bootstrap      → Analyze emails (one-shot)
  python run.py dashboard      → View results

📖 DOCUMENTATION:

  QUICK_START.md              → Quick start guide
  EMAIL_DASHBOARD_GUIDE.md    → Dashboard features
  DEMO_MODE_GUIDE.md          → Demo mode details

🐛 TROUBLESHOOTING:

  python debug_emails.py --check     → Check email database
  python check_url_matching.py URL   → Test URL matching

💡 TYPICAL WORKFLOW:

  1. python run.py demo --once     (First time setup & test)
  2. python run.py dashboard       (View results)
  3. python run.py demo            (Start monitoring)

Press Enter to return to menu...
            """)
            input()
            
        elif choice in ['q', 'quit', 'exit']:
            print("\n👋 Goodbye!\n")
            sys.exit(0)
            
        else:
            print(f"\n❌ Invalid choice: '{choice}'")
            print("   Please enter 1-5 or Q")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!\n")
        sys.exit(0)

