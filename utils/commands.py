#!/usr/bin/env python3
"""
Quick reference for all available run commands.
Execute this to see all commands and their usage.
"""

COMMANDS = {
    "MAIN RUNNER (run.py)": {
        "Setup": [
            ("Full setup", "python run.py setup"),
            ("Fast setup", "python run.py setup --fast-enrich"),
            ("Setup with limits", "python run.py setup --enrich-limit 500"),
        ],
        "Database": [
            ("Init schemas", "python run.py db"),
            ("Fetch threats", "python run.py fetch"),
            ("Enrich data", "python run.py enrich --limit 100"),
            ("Fast enrich", "python run.py enrich --limit 100 --disable-whois --disable-ipwhois"),
        ],
        "Gmail": [
            ("Authenticate", "python run.py auth"),
            ("Fetch emails", "python run.py emails --count 10"),
            ("Enrich emails", "python run.py enrich-emails"),
        ],
        "Services": [
            ("Run API", "python run.py api"),
            ("Run API (dev)", "python run.py api --reload"),
            ("Run API (custom)", "python run.py api --port 8080"),
            ("Run dashboard", "python run.py dashboard"),
        ],
    },
    "SHELL SCRIPTS (Bash)": {
        "Setup": [
            ("Full setup", "./setup.sh"),
        ],
        "Services": [
            ("Run API", "./run.sh"),
            ("Run dashboard", "./run_dashboard.sh"),
        ],
    },
    "SHELL SCRIPTS (Fish)": {
        "Setup": [
            ("Full setup", "./setup.fish"),
        ],
        "Services": [
            ("Run API", "./run.fish"),
            ("Run dashboard", "./run_dashboard.fish"),
        ],
    },
    "PYTHON MODULES (Direct)": {
        "Database": [
            ("Init raw DB", "python -m app.database.rawdb"),
            ("Init enriched DB", "python -m app.database.db"),
            ("Fetch threats", "python -m app.database.grabrawdata"),
            ("Enrich data", "python -m app.database.enrich --limit 100"),
        ],
        "Detector": [
            ("Setup DB", "python -m app.detector.core --setup-db"),
            ("Authenticate", "python -m app.detector.core --authenticate"),
            ("Fetch emails", "python -m app.detector.core --fetch 10"),
            ("Enrich email", "python -m app.detector.core --enrich-email <id>"),
            ("Enrich all", "python -m app.detector.core --enrich-all"),
        ],
        "Services": [
            ("Run API", "python -m uvicorn app.main:app --reload"),
            ("Run dashboard", "python -m streamlit run app/dashboard/frontend.py"),
        ],
    },
}


def print_commands():
    """Print all commands in organized format."""
    print("=" * 70)
    print("PHISHING DETECTOR - COMMAND REFERENCE")
    print("=" * 70)
    print()
    
    for category, sections in COMMANDS.items():
        print(f"\n{category}")
        print("-" * 70)
        for section, commands in sections.items():
            print(f"\n  {section}:")
            for desc, cmd in commands:
                print(f"    • {desc:20} {cmd}")
    
    print("\n" + "=" * 70)
    print("QUICK START")
    print("=" * 70)
    print("  1. python run.py setup          # Full setup")
    print("  2. python run.py auth           # Authenticate Gmail")
    print("  3. python run.py api            # Run API server")
    print("  4. python run.py dashboard      # Run dashboard")
    print("=" * 70)


if __name__ == "__main__":
    print_commands()
