# Usage:
# python3 main.py
#   --api_endpoint https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner\

import argparse
import time

from lib.colors import red, green, yellow
from lib.logger import logger
from lib.parsers.WordfenceAPIParser import WordfenceAPIParser


parser = argparse.ArgumentParser(description='Process a Wordfence CVE report')
parser.add_argument('--api_endpoint', required=False, help='API endpoint containing Wordfence CVE reports')
parser.add_argument('--force', required=False, help='ignore if there is already a template in the official nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--overwrite', required=False, help='ignore if there is already a template in our local nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--overwrite_enhanced', required=False, help='ignore if there is already an **enhanced** template in our local nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--threads', required=False, help='boost by increasing the default worker threads (default 2)', default=2, type=int)
args = parser.parse_args()

def main():
    ts = time.time()

    if args.api_endpoint is None:
        logger.warning("Please pass an API endpoint URL (--api_endpoint) to process.")
        exit(1)
        
    
    logger.info(yellow('API mode'))
    
    parser = WordfenceAPIParser()
    parser.run(args.api_endpoint, args.overwrite, args.force, args.overwrite_enhanced)

    logger.info('Done. Took %s', time.strftime("%H:%M:%S", time.gmtime(time.time() - ts)))


if __name__ == '__main__':
    main()
    