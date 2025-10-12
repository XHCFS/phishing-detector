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
    """Fetch emails from Gmail."""
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
        description="Phishing Detector - Centralized runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py setup                    # Full setup (db + fetch + enrich)
  python run.py setup --fast-enrich      # Quick setup with minimal enrichment
  python run.py fetch                    # Fetch threat feeds only
  python run.py enrich --limit 100       # Enrich 100 URLs
  python run.py auth                     # Authenticate Gmail
  python run.py emails --count 10        # Fetch 10 recent emails
  python run.py api                      # Run FastAPI server
  python run.py dashboard                # Run Streamlit dashboard
  python run.py api --port 8080          # Run API on custom port
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Full setup (database + fetch + enrich)")
    setup_parser.add_argument("--skip-detector", action="store_true", help="Skip detector database setup")
    setup_parser.add_argument("--skip-openphish", action="store_true", help="Skip OpenPhish feed")
    setup_parser.add_argument("--skip-phishtank", action="store_true", help="Skip PhishTank feed")
    setup_parser.add_argument("--skip-urlhaus", action="store_true", help="Skip URLhaus feed")
    setup_parser.add_argument("--enrich-limit", type=int, default=1000, help="URLs to enrich during setup")
    setup_parser.add_argument("--fast-enrich", action="store_true", help="Skip slow enrichment steps")
    
    # Database command
    db_parser = subparsers.add_parser("db", help="Initialize database schemas only")
    db_parser.add_argument("--skip-detector", action="store_true", help="Skip detector database setup")
    
    # Fetch command
    fetch_parser = subparsers.add_parser("fetch", help="Fetch threat feeds")
    fetch_parser.add_argument("--skip-openphish", action="store_true", help="Skip OpenPhish feed")
    fetch_parser.add_argument("--skip-phishtank", action="store_true", help="Skip PhishTank feed")
    fetch_parser.add_argument("--skip-urlhaus", action="store_true", help="Skip URLhaus feed")
    
    # Enrich command
    enrich_parser = subparsers.add_parser("enrich", help="Enrich threat feed data")
    enrich_parser.add_argument("--limit", type=int, help="Limit number of URLs to process")
    enrich_parser.add_argument("--skip-existing", action="store_true", help="Skip already enriched URLs")
    enrich_parser.add_argument("--source", choices=["openphish", "phishtank", "urlhaus"], help="Process specific source only")
    enrich_parser.add_argument("--disable-whois", action="store_true", help="Disable WHOIS lookups")
    enrich_parser.add_argument("--disable-ipwhois", action="store_true", help="Disable IP WHOIS lookups")
    enrich_parser.add_argument("--disable-page-content", action="store_true", help="Disable page content fetching")
    enrich_parser.add_argument("--concurrency", type=int, help="Concurrent URL processing")
    enrich_parser.add_argument("--workers", type=int, help="Worker thread pool size")
    
    # Auth command
    auth_parser = subparsers.add_parser("auth", help="Authenticate with Gmail")
    auth_parser.add_argument("--credentials", help="Path to credentials.json")
    
    # Emails command
    emails_parser = subparsers.add_parser("emails", help="Fetch and process emails")
    emails_parser.add_argument("--count", type=int, default=25, help="Number of emails to fetch")
    emails_parser.add_argument("--credentials", help="Path to credentials.json")
    
    # Enrich emails command
    enrich_emails_parser = subparsers.add_parser("enrich-emails", help="Enrich fetched emails")
    enrich_emails_parser.add_argument("--email-id", help="Specific email ID to enrich")
    enrich_emails_parser.add_argument("--credentials", help="Path to credentials.json")
    
    # API command
    api_parser = subparsers.add_parser("api", help="Run FastAPI server")
    api_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    api_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    api_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Run Streamlit dashboard")
    dashboard_parser.add_argument("--host", default="localhost", help="Host to bind to")
    dashboard_parser.add_argument("--port", type=int, default=8501, help="Port to bind to")
    
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
        "api": run_api,
        "dashboard": run_dashboard,
    }
    
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
