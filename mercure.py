#!/usr/bin/env python3
import sys

from mercure.cli import main

if __name__ == "__main__":
   try:
      main()
   except KeyboardInterrupt:
      sys.exit(130)
   except Exception as exc:
      from mercure import logger
      logger.error(f"unhandled error: {exc}")
      sys.exit(1)
