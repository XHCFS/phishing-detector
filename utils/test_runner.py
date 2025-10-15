#!/usr/bin/env python3
"""Test runner for all run.py commands."""
import subprocess
import sys

def run_cmd(cmd):
    """Run command and return True if successful."""
    print(f"\n{'='*60}")
    print(f"Testing: {cmd}")
    print('='*60)
    result = subprocess.run(cmd, shell=True, capture_output=False)
    return result.returncode == 0

def main():
    """Test all run.py commands."""
    tests = [
        ("Help", "python run.py --help"),
        ("DB init", "python run.py db"),
        ("Fetch help", "python run.py fetch --help"),
        ("Enrich help", "python run.py enrich --help"),
        ("Auth help", "python run.py auth --help"),
        ("Emails help", "python run.py emails --help"),
        ("API help", "python run.py api --help"),
        ("Dashboard help", "python run.py dashboard --help"),
    ]
    
    passed = 0
    failed = 0
    
    for name, cmd in tests:
        if run_cmd(cmd):
            print(f"✅ {name} passed")
            passed += 1
        else:
            print(f"❌ {name} failed")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed} passed, {failed} failed")
    print('='*60)
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
