#!/usr/bin/env python3
"""
Simple runner script for Obscurio password manager.
This allows running from project root without installing.
"""
import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from obscurio import main
    main()
except ImportError as e:
    print(f"Error importing Obscurio: {e}")
    print("Make sure you're in the project root directory")
    sys.exit(1)
