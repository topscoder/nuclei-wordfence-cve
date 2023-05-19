# Usage:
# python3 main.py
#   --url https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/tenweb-speed-optimizer/10web-booster-website-speed-optimization-cache-page-speed-optimizer-21344-missing-authorization-in-settings-import-to-stored-cross-site-scripting
#   --outputfile cve-1234-09876.yaml

from lib.colors import red, green, yellow

from queue import Queue
import time
from lib.DownloadWorker import DownloadWorker
from lib.logger import logger
import argparse
from lib.parsers.WordfenceAPIParser import WordfenceAPIParser

from lib.parsers.WordfenceParser import WordfenceParser


parser = argparse.ArgumentParser(description='Process a Wordfence CVE report')
parser.add_argument('--api_endpoint', required=False, help='API endpoint containing Wordfence CVE reports')
# parser.add_argument('--url', required=False, help='the URL of the Wordfence CVE report. eg https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/houzez-login-register/houzez-login-register-263-privilege-escalation')
# parser.add_argument('--outputfile', required=False, help='the output filename to store the nuclei-template in', default="")
parser.add_argument('--force', required=False, help='ignore if there is already a template in the official nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--overwrite', required=False, help='ignore if there is already a template in our local nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--overwrite_enhanced', required=False, help='ignore if there is already an **enhanced** template in our local nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--threads', required=False, help='boost by increasing the default worker threads (default 2)', default=2, type=int)
# parser.add_argument('--warningsfile', required=False, help='filename to store warnings in so its possible to investigate issues', default=False, action='store_true')
args = parser.parse_args()


WORKER_THREADS = int(args.threads)
logger.info(f"Setting threads to {WORKER_THREADS}")


def main():
    ts = time.time()

    if args.api_endpoint is None:
        logger.warning("Please pass a API endpoint URL (--api_endpoint) to process.")
        exit(1)
        
    # Input file (multi URL) mode
    if args.api_endpoint is not None:
        logger.info(yellow('API mode'))
        
        parser = WordfenceAPIParser()
        parser.run(args.api_endpoint, outputfile="", overwrite=False, force=False, overwrite_enhanced=False)

    logger.info('Done. Took %s', time.strftime("%H:%M:%S", time.gmtime(time.time() - ts)))


if __name__ == '__main__':
    main()
    