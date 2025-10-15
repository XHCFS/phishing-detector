#!/usr/bin/env python3
"""
Centralized runner for phishing detector system.
Manages setup, data fetching, enrichment, and service launching.
"""
import sys
import subprocess
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
VENV_DIR = PROJECT_ROOT / ".venv"
VENV_PYTHON = VENV_DIR / "bin" / "python"


def check_venv():
    """Check if virtual environment exists."""
    if not VENV_DIR.exists():
        print("❌ Virtual environment not found.")
        print("   Run: python3 -m venv .venv")
        print("   Then: source .venv/bin/activate.fish")
        print("   Then: pip install -r requirements.txt")
        sys.exit(1)
    if not VENV_PYTHON.exists():
        print("❌ Python interpreter not found in virtual environment.")
        sys.exit(1)


def run_python_module(module, args=None):
    """Run a Python module with arguments."""
    cmd = [str(VENV_PYTHON), "-m", module]
    if args:
        cmd.extend(args)
    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    return result.returncode


def run_command(cmd):
    """Run a shell command."""
    result = subprocess.run(cmd, shell=True, cwd=PROJECT_ROOT)
    return result.returncode


def setup_database(args):
    """Initialize database schema."""
    print("📦 Setting up database schemas...")
    
    print("  → Creating raw threat feeds database...")
    if run_python_module("app.database.rawdb") != 0:
        print("❌ Failed to create raw database")
        return 1
    
    print("  → Creating enriched database...")
    if run_python_module("app.database.db") != 0:
        print("❌ Failed to create enriched database")
        return 1
    
    if not args.skip_detector:
        print("  → Setting up detector database...")
        if run_python_module("app.detector.core", ["--setup-db"]) != 0:
            print("⚠️  Failed to create detector database (optional)")
    
    print("✅ Database setup complete")
    return 0


def fetch_threats(args):
    """Fetch threat feed data."""
    print("🌐 Fetching threat feeds...")
    
    cmd_args = []
    if args.skip_openphish:
        cmd_args.append("--skip-openphish")
    if args.skip_phishtank:
        cmd_args.append("--skip-phishtank")
    if args.skip_urlhaus:
        cmd_args.append("--skip-urlhaus")
    
    if run_python_module("app.database.grabrawdata", cmd_args) != 0:
        print("❌ Failed to fetch threat feeds")
        return 1
    
    print("✅ Threat feeds fetched")
    return 0


def enrich_data(args):
    """Enrich threat feed data."""
    print("🔍 Enriching threat feed data...")
    
    cmd_args = []
    if args.limit:
        cmd_args.extend(["--limit", str(args.limit)])
    if args.skip_existing:
        cmd_args.append("--skip-existing")
    if args.source:
        cmd_args.extend(["--source", args.source])
    if args.disable_whois:
        cmd_args.append("--disable-whois")
    if args.disable_ipwhois:
        cmd_args.append("--disable-ipwhois")
    if args.disable_page_content:
        cmd_args.append("--disable-page-content")
    if args.concurrency:
        cmd_args.extend(["--concurrency", str(args.concurrency)])
    if args.workers:
        cmd_args.extend(["--workers", str(args.workers)])
    
    if run_python_module("app.database.enrich", cmd_args) != 0:
        print("❌ Failed to enrich data")
        return 1
    
    print("✅ Data enrichment complete")
    return 0


def authenticate_gmail(args):
    """Authenticate with Gmail API."""
    print("🔐 Starting Gmail authentication...")
    print("    A browser window will open for OAuth authentication.")
    
    cmd_args = ["--authenticate"]
    if args.credentials:
        cmd_args.extend(["--credentials", args.credentials])
    
    if run_python_module("app.detector.core", cmd_args) != 0:
        print("❌ Gmail authentication failed")
        return 1
    
    print("✅ Gmail authentication complete")
    return 0


def fetch_emails(args):
    """Fetch emails from Gmail and optionally enrich them."""
    print("📧 Fetching emails from Gmail...")
    
    cmd_args = ["--fetch"]
    if args.count:
        cmd_args.append(str(args.count))
    if args.credentials:
        cmd_args.extend(["--credentials", args.credentials])
    
    if run_python_module("app.detector.core", cmd_args) != 0:
        print("❌ Failed to fetch emails")
        return 1
    
    print("✅ Emails fetched")
    
    # Auto-enrich if requested
    if args.enrich:
        print("\n🔍 Enriching fetched emails...")
        enrich_args = argparse.Namespace(email_id=None, credentials=args.credentials)
        if enrich_emails(enrich_args) != 0:
            print("⚠️  Email enrichment had issues, but fetch succeeded")
    
    return 0


def enrich_emails(args):
    """Enrich emails with threat data."""
    print("🔍 Enriching emails...")
    
    if args.email_id:
        cmd_args = ["--enrich-email", args.email_id]
    else:
        cmd_args = ["--enrich-all"]
    
    if args.credentials:
        cmd_args.extend(["--credentials", args.credentials])
    
    if run_python_module("app.detector.core", cmd_args) != 0:
        print("❌ Failed to enrich emails")
        return 1
    
    print("✅ Email enrichment complete")
    return 0


def bootstrap_emails(args):
    """Bootstrap: fetch and enrich emails in one shot."""
    print("🚀 Bootstrapping email processing...")
    
    cmd_args = ["--bootstrap", f"--max-fetch={args.count}"]
    if args.credentials:
        cmd_args.extend(["--credentials", args.credentials])
    
    if run_python_module("app.detector.core", cmd_args) != 0:
        print("❌ Email bootstrap failed")
        return 1
    
    print("✅ Email bootstrap complete")
    return 0


def demo_mode(args):
    """Demo mode: Complete setup + continuous email monitoring + auto-dashboard."""
    import time
    import multiprocessing
    import signal
    import os
    
    print("🎬 Starting DEMO MODE")
    print("=" * 70)
    print()
    
    # Step 1: Quick setup if needed
    print("📋 Step 1: Checking setup...")
    db_path = PROJECT_ROOT / "app" / "database" / "threat_feeds.db"
    
    if not db_path.exists() or args.force_setup:
        print("   Running quick setup...\n")
        setup_args = argparse.Namespace(
            skip_detector=False,
            skip_openphish=args.skip_openphish,
            skip_phishtank=args.skip_phishtank,
            skip_urlhaus=args.skip_urlhaus,
            enrich_limit=500,  # Quick setup
            fast_enrich=True   # Skip slow enrichments
        )
        if full_setup(setup_args) != 0:
            print("❌ Setup failed")
            return 1
    else:
        print("   ✓ Database exists, skipping setup")
        print("   (Use --force-setup to re-run setup)\n")
    
    # Step 2: Gmail auth check
    print("📋 Step 2: Checking Gmail authentication...")
    token_path = PROJECT_ROOT / "app" / "detector" / "token.json"
    
    if not token_path.exists():
        print("   Gmail not authenticated. Starting OAuth flow...\n")
        auth_args = argparse.Namespace(credentials=args.credentials)
        if authenticate_gmail(auth_args) != 0:
            print("❌ Gmail authentication failed")
            return 1
    else:
        print("   ✓ Gmail already authenticated\n")
    
    # Step 3: Start dashboard in background (if not --no-dashboard)
    dashboard_process = None
    if not args.no_dashboard:
        print("📋 Step 3: Starting dashboard...")
        
        # Create trigger file for dashboard auto-refresh
        trigger_file = PROJECT_ROOT / ".demo_refresh_trigger"
        trigger_file.write_text(str(time.time()))
        
        print(f"   Dashboard URL: http://localhost:{args.dashboard_port}")
        print("   Auto-refresh: Every 10 seconds + after each email fetch\n")
        
        # Start dashboard in background
        env = os.environ.copy()
        env['DEMO_MODE'] = '1'
        env['DEMO_TRIGGER_FILE'] = str(trigger_file)
        
        dashboard_process = subprocess.Popen(
            [str(VENV_PYTHON), "-m", "streamlit", "run",
             "app/dashboard/frontend.py",
             "--server.port", str(args.dashboard_port),
             "--server.address", "localhost",
             "--server.headless", "true",
             "--browser.gatherUsageStats", "false"],
            cwd=PROJECT_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for dashboard to start
        print("   Waiting for dashboard to start...")
        time.sleep(3)
        print("   ✓ Dashboard started in background\n")
    else:
        print("📋 Step 3: Dashboard disabled (--no-dashboard flag)\n")
        trigger_file = None
    
    # Step 4: Continuous email monitoring
    step_num = 4 if not args.no_dashboard else 3
    print(f"📋 Step {step_num}: Starting continuous email monitoring")
    print(f"   Fetch interval: {args.interval} seconds")
    print(f"   Emails per fetch: {args.count}")
    if dashboard_process:
        print(f"   Dashboard: http://localhost:{args.dashboard_port}")
    print("   Press Ctrl+C to stop\n")
    print("=" * 70)
    print()
    
    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"\n{'='*70}")
            print(f"📧 Iteration {iteration} - {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*70}\n")
            
            # Fetch and enrich emails
            bootstrap_args = argparse.Namespace(count=args.count, credentials=args.credentials)
            if bootstrap_emails(bootstrap_args) != 0:
                print("⚠️  Email processing failed, will retry next iteration")
            
            # Update trigger file for dashboard refresh
            if trigger_file:
                trigger_file.write_text(str(time.time()))
                print("\n🔄 Dashboard auto-refresh triggered")
            
            # Show statistics
            print("\n📊 Current Statistics:")
            run_command(f'{VENV_PYTHON} -c "import sqlite3; conn = sqlite3.connect(\'{db_path}\'); cur = conn.cursor(); cur.execute(\'SELECT COUNT(*) FROM emails\'); print(f\'   Total emails: {{cur.fetchone()[0]}}\'); cur.execute(\'SELECT COUNT(*) FROM emails WHERE risk_score >= 85\'); print(f\'   Critical risk: {{cur.fetchone()[0]}}\'); cur.execute(\'SELECT COUNT(*) FROM emails WHERE risk_score >= 70 AND risk_score < 85\'); print(f\'   High risk: {{cur.fetchone()[0]}}\'); conn.close()"')
            
            # Wait for next iteration
            if not args.once:
                print(f"\n⏱️  Waiting {args.interval} seconds until next fetch...")
                if dashboard_process:
                    print(f"   Dashboard running at: http://localhost:{args.dashboard_port}")
                print(f"   (Press Ctrl+C to stop)")
                time.sleep(args.interval)
            else:
                print("\n✅ Single iteration complete (--once mode)")
                if dashboard_process:
                    print(f"\n📊 Dashboard still running at: http://localhost:{args.dashboard_port}")
                    print("   Press Ctrl+C to stop dashboard...")
                    dashboard_process.wait()
                break
                
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo mode stopped by user")
        print(f"   Completed {iteration} iterations")
        
        # Stop dashboard
        if dashboard_process:
            print("   Stopping dashboard...")
            dashboard_process.terminate()
            try:
                dashboard_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dashboard_process.kill()
        
        # Clean up trigger file
        if trigger_file and trigger_file.exists():
            trigger_file.unlink()
        
        return 0
    
    return 0


def run_api(args):
    """Run the FastAPI server."""
    print("🚀 Starting FastAPI server...")
    print(f"    URL: http://{args.host}:{args.port}")
    print("    Press Ctrl+C to stop")
    print()
    
    cmd = [
        str(VENV_PYTHON), "-m", "uvicorn",
        "app.main:app",
        "--host", args.host,
        "--port", str(args.port)
    ]
    if args.reload:
        cmd.append("--reload")
    
    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    return result.returncode


def run_dashboard(args):
    """Run the Streamlit dashboard."""
    print("📊 Starting Streamlit dashboard...")
    print(f"    URL: http://{args.host}:{args.port}")
    print("    Press Ctrl+C to stop")
    print()
    
    db_path = PROJECT_ROOT / "app" / "database" / "threat_feeds.db"
    if not db_path.exists():
        print("❌ Enriched database not found.")
        print("   Run: python run.py enrich")
        return 1
    
    cmd = [
        str(VENV_PYTHON), "-m", "streamlit", "run",
        "app/dashboard/frontend.py",
        "--server.port", str(args.port),
        "--server.address", args.host,
        "--browser.gatherUsageStats", "false"
    ]
    
    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    return result.returncode


def full_setup(args):
    """Run complete setup process."""
    print("🔧 Running full setup...\n")
    
    if setup_database(args) != 0:
        return 1
    
    print()
    if fetch_threats(args) != 0:
        return 1
    
    print()
    limit_args = argparse.Namespace(
        limit=args.enrich_limit,
        skip_existing=False,
        source=None,
        disable_whois=args.fast_enrich,
        disable_ipwhois=args.fast_enrich,
        disable_page_content=args.fast_enrich,
        concurrency=None,
        workers=None
    )
    if enrich_data(limit_args) != 0:
        return 1
    
    print("\n✅ Full setup complete!")
    print("\nNext steps:")
    print("  • Authenticate Gmail: python run.py auth")
    print("  • Run API server:     python run.py api")
    print("  • Run dashboard:      python run.py dashboard")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="🔒 Phishing Email Detector - Simple Command Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 QUICK START (Choose One):

  python run.py demo              → Auto-everything + dashboard (continuous)
  python run.py demo --once       → Test once (dashboard stays open)
  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📧 EMAIL COMMANDS (Most Common):

  python run.py auth              → Authenticate Gmail (do this first!)
  python run.py bootstrap         → Fetch + analyze emails (one shot)
  python run.py emails --enrich   → Fetch + analyze emails (same as bootstrap)
  
  python run.py dashboard         → Open web dashboard to view results
  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚙️  ADVANCED (Optional):

  Setup:
    python run.py setup           → Full threat database setup
    python run.py setup --fast    → Quick setup (skip slow enrichments)
  
  Threat Feeds:
    python run.py fetch           → Download threat feeds
    python run.py enrich          → Enrich threat data
  
  Email Management:
    python run.py emails          → Just fetch emails (no analysis)
    python run.py enrich-emails   → Analyze already-fetched emails
  
  Server:
    python run.py api             → Run API server
  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 TYPICAL WORKFLOW:

  1. python run.py demo --once    (Auto-setup + test with 5 emails)
  2. python run.py dashboard      (View results in browser)
  3. python run.py demo            (Start continuous monitoring)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # ========================================================================
    # PRIMARY COMMANDS (Simple, common use)
    # ========================================================================
    
    # Demo mode - The easiest way to get started
    demo_parser = subparsers.add_parser(
        "demo", 
        help="🎬 Auto-setup + email monitoring (EASIEST)",
        description="Complete auto-setup and continuous email monitoring"
    )
    demo_parser.add_argument("--once", action="store_true", help="Run once and exit (no loop)")
    demo_parser.add_argument("--count", type=int, default=5, help="Emails per fetch (default: 5)")
    demo_parser.add_argument("--interval", type=int, default=300, help="Seconds between fetches (default: 300)")
    demo_parser.add_argument("--no-dashboard", action="store_true", help="Don't auto-launch dashboard")
    demo_parser.add_argument("--dashboard-port", type=int, default=8501, help="Dashboard port (default: 8501)")
    demo_parser.add_argument("--force-setup", action="store_true", help="Force database re-setup")
    demo_parser.add_argument("--credentials", help="Path to Gmail credentials.json")
    demo_parser.add_argument("--skip-openphish", action="store_true", help="[Advanced] Skip feed")
    demo_parser.add_argument("--skip-phishtank", action="store_true", help="[Advanced] Skip feed")
    demo_parser.add_argument("--skip-urlhaus", action="store_true", help="[Advanced] Skip feed")
    
    # Auth - Gmail authentication
    auth_parser = subparsers.add_parser(
        "auth",
        help="🔐 Authenticate Gmail",
        description="Complete Gmail OAuth authentication"
    )
    auth_parser.add_argument("--credentials", help="Path to credentials.json")
    
    # Bootstrap - Fetch and analyze emails in one shot
    bootstrap_parser = subparsers.add_parser(
        "bootstrap",
        help="📧 Fetch + analyze emails (one-shot)",
        description="Fetch emails and analyze them for threats"
    )
    bootstrap_parser.add_argument("--count", type=int, default=10, help="Number of emails (default: 10)")
    bootstrap_parser.add_argument("--credentials", help="Path to credentials.json")
    
    # Dashboard - View results in web UI
    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="📊 Open web dashboard",
        description="Launch Streamlit dashboard to view email threats"
    )
    dashboard_parser.add_argument("--host", default="localhost", help="Host (default: localhost)")
    dashboard_parser.add_argument("--port", type=int, default=8501, help="Port (default: 8501)")
    
    # ========================================================================
    # SECONDARY COMMANDS (Advanced users)
    # ========================================================================
    
    # Setup
    setup_parser = subparsers.add_parser(
        "setup",
        help="⚙️  [Advanced] Full database setup",
        description="Initialize database and threat feeds"
    )
    setup_parser.add_argument("--fast", dest="fast_enrich", action="store_true", help="Quick mode")
    setup_parser.add_argument("--enrich-limit", type=int, default=1000, help="URLs to enrich")
    setup_parser.add_argument("--skip-detector", action="store_true", help="Skip email DB")
    setup_parser.add_argument("--skip-openphish", action="store_true", help="Skip feed")
    setup_parser.add_argument("--skip-phishtank", action="store_true", help="Skip feed")
    setup_parser.add_argument("--skip-urlhaus", action="store_true", help="Skip feed")
    
    # Emails (fetch only)
    emails_parser = subparsers.add_parser(
        "emails",
        help="📬 [Advanced] Fetch emails",
        description="Fetch emails from Gmail (use bootstrap instead)"
    )
    emails_parser.add_argument("--count", type=int, default=25, help="Number of emails")
    emails_parser.add_argument("--enrich", action="store_true", help="Also analyze emails")
    emails_parser.add_argument("--credentials", help="Path to credentials.json")
    
    # Less common commands with minimal options
    subparsers.add_parser("db", help="[Advanced] Create database schema")
    subparsers.add_parser("fetch", help="[Advanced] Download threat feeds")
    
    enrich_parser = subparsers.add_parser("enrich", help="[Advanced] Enrich threat data")
    enrich_parser.add_argument("--limit", type=int, help="Max URLs to process")
    enrich_parser.add_argument("--skip-existing", action="store_true", help="Skip already enriched")
    enrich_parser.add_argument("--source", choices=["openphish", "phishtank", "urlhaus"], help="Specific source")
    enrich_parser.add_argument("--disable-whois", action="store_true", help="Disable WHOIS")
    enrich_parser.add_argument("--disable-ipwhois", action="store_true", help="Disable IP WHOIS")
    enrich_parser.add_argument("--disable-page-content", action="store_true", help="Disable page fetch")
    enrich_parser.add_argument("--concurrency", type=int, help="Concurrent URLs")
    enrich_parser.add_argument("--workers", type=int, help="Worker threads")
    
    enrich_emails_parser = subparsers.add_parser("enrich-emails", help="[Advanced] Analyze fetched emails")
    enrich_emails_parser.add_argument("--email-id", help="Specific email ID")
    enrich_emails_parser.add_argument("--credentials", help="Path to credentials.json")
    
    api_parser = subparsers.add_parser("api", help="[Advanced] Run API server")
    api_parser.add_argument("--host", default="0.0.0.0", help="Host")
    api_parser.add_argument("--port", type=int, default=8000, help="Port")
    api_parser.add_argument("--reload", action="store_true", help="Auto-reload")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    check_venv()
    
    commands = {
        "setup": full_setup,
        "db": setup_database,
        "fetch": fetch_threats,
        "enrich": enrich_data,
        "auth": authenticate_gmail,
        "emails": fetch_emails,
        "enrich-emails": enrich_emails,
        "bootstrap": bootstrap_emails,
        "demo": demo_mode,
        "api": run_api,
        "dashboard": run_dashboard,
    }
    
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
