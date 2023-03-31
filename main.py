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


parser = argparse.ArgumentParser(description='Process a Wordfence CVE report')
parser.add_argument('--inputfile', required=False, help='file containing Urls to Wordfence CVE reports')
parser.add_argument('--url', required=False, help='the URL of the Wordfence CVE report. eg https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/houzez-login-register/houzez-login-register-263-privilege-escalation')
parser.add_argument('--outputfile', required=False, help='the output filename to store the nuclei-template in', default="")
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
    urls = []

    if args.url is None and args.inputfile is None:
        logger.warning("Please pass a url (--url) or a file (--inputfile) to process.")
        exit(1)

    # Single URL mode
    if args.url is not None:
        logger.info(yellow('Single URL mode'))
        urls.append(args.url)
        
    # Input file (multi URL) mode
    if args.inputfile is not None:
        logger.info(yellow('Multi URL mode'))
        with open(args.inputfile, 'r') as inp:
            for line in inp.readlines():
                if line.strip() != "":
                    urls.append(line)

    queue = Queue()
    for x in range(WORKER_THREADS):
        worker = DownloadWorker(queue)
        worker.daemon = True
        worker.start()
    
    for url in urls:
        queue.put((url, args.outputfile, args.overwrite, args.force, args.overwrite_enhanced))
    
    queue.join()
    logger.info('Done. Took %s', time.strftime("%H:%M:%S", time.gmtime(time.time() - ts)))


if __name__ == '__main__':
    main()
    