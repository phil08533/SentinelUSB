#!/usr/bin/env python3
"""SentinelUSB terminal interface."""

BANNER = r"""
   _____            __  _ __      __ __  ______  ____ 
  / ___/__  ____   / /_(_) /___ _/ // / / __/ / / / /
  \__ \/ _ \/ __ \ / __/ / / __ `/ // /_/ /_/ /_/ / 
 ___/ /  __/ / / // /_/ / / /_/ /__  __/ __/ __  /  
/____/\___/_/ /_/ \__/_/_/\__,_/  /_/ /_/ /_/ /_/   
                 S E N T I N E L
"""

def main() -> None:
    print(BANNER)
    print("  SentinelUSB Security Rescue Environment")
    print("  ----------------------------------------")
    print("  Type 'help' for available commands.")
    print()

if __name__ == "__main__":
    main()
