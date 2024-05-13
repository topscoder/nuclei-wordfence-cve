# Usage:
# python3 main.py
#   --api_endpoint https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner

import argparse
import time

from lib.colors import yellow
from lib.logger import logger
from lib.parsers.WordfenceAPIParser import WordfenceAPIParser
from lib.parsers.WordfenceParser import WordfenceParser


parser = argparse.ArgumentParser(description='Process a Wordfence CVE report')
parser.add_argument('--api_endpoint', required=False, help='API endpoint containing Wordfence CVE reports')
parser.add_argument('--single_url', required=False, help='Single URL containing Wordfence CVE report')
parser.add_argument('--force', required=False, help='ignore if there is already a template in the official nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--overwrite', required=False, help='ignore if there is already a template in our local nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--overwrite_enhanced', required=False, help='ignore if there is already an **enhanced** template in our local nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--threads', required=False, help='boost by increasing the default worker threads (default 2)', default=2, type=int)
args = parser.parse_args()


def main():
    ts = time.time()

    if args.api_endpoint is None and args.single_url is None:
        logger.warning("Please pass either an API endpoint URL (--api_endpoint) or a URL to a single CVE report (--single_url) to process.")
        exit(1)

    if args.api_endpoint is not None:
        logger.info(yellow('API mode'))

        parser = WordfenceAPIParser()
        parser.run(args.api_endpoint, args.overwrite, args.force, args.overwrite_enhanced)

    elif args.single_url is not None:
        logger.info(yellow('Single page mode'))

        parser = WordfenceParser()
        parser.run(args.single_url, None, args.overwrite, args.force, args.overwrite_enhanced)

    logger.info('Done. Took %s', time.strftime("%H:%M:%S", time.gmtime(time.time() - ts)))


if __name__ == '__main__':
    main()
