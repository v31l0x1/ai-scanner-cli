#!/usr/bin/env python3
"""
Setup script for AI Code Scanner CLI
"""

import subprocess
import sys
import os

def install_requirements():
    """Install required packages"""
    print("Installing required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Requirements installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing requirements: {e}")
        sys.exit(1)

def setup_environment():
    """Setup environment file"""
    if not os.path.exists('.env'):
        print("Setting up environment file...")
        with open('.env.example', 'r') as example:
            content = example.read()
        
        with open('.env', 'w') as env_file:
            env_file.write(content)
        
        print("✅ Environment file created (.env)")
        print("📝 Please edit .env and add your Gemini API key")
    else:
        print("✅ Environment file already exists")

def main():
    """Main setup function"""
    print("🚀 Setting up AI Code Scanner CLI...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    
    # Install requirements
    install_requirements()
    
    # Setup environment
    setup_environment()
    
    print("\n🎉 Setup complete!")
    print("\nNext steps:")
    print("1. Edit .env file and add your Gemini API key")
    print("2. Run: python main.py test (to test API connection)")
    print("3. Run: python main.py scan --help (to see all options)")
    print("4. Run: python main.py scan (to start scanning)")

if __name__ == "__main__":
    main()
