# Usage:
# python3 main.py
#   --api_endpoint https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner

import argparse
import time
from lib.colors import yellow
from lib.logger import logger
from lib.wordfence_api_parser import WordfenceAPIParser
from lib.wordfence_parser import WordfenceParser


def main():
    ts = time.time()

    parser = argparse.ArgumentParser(description='Generate Nuclei templates of Wordfence vulnerabilities')

    required_group = parser.add_mutually_exclusive_group(required=True)
    required_group.add_argument('--api_endpoint', required=False, help='API endpoint containing Wordfence CVE reports')
    required_group.add_argument('--single_url', required=False, help='Single URL containing Wordfence CVE report')
    required_group.add_argument('--local_file', required=False, help='Local file containing the vulnerabilities in JSON format (probably the output of Wordfence API)')

    parser.add_argument('--force', required=False, help='ignore if there is already a template in the official nuclei-templates repo', default=False, action='store_true')
    parser.add_argument('--overwrite', required=False, help='ignore if there is already a template in our local nuclei-templates repo', default=False, action='store_true')
    parser.add_argument('--overwrite_enhanced', required=False, help='ignore if there is already an **enhanced** template in our local nuclei-templates repo', default=False, action='store_true')
    parser.add_argument('--threads', required=False, help='boost by increasing the default worker threads (default 2)', default=2, type=int)
    args = parser.parse_args()

    if args.api_endpoint is not None:
        logger.info(yellow('API mode'))

        parser = WordfenceAPIParser()
        parser.run(args.api_endpoint, args.overwrite, args.force, args.overwrite_enhanced)

    elif args.local_file is not None:
        logger.info(yellow('Local file mode'))

        parser = WordfenceAPIParser()
        parser.run_local(args.local_file, args.overwrite, args.force, args.overwrite_enhanced)

    elif args.single_url is not None:
        logger.info(yellow('Single page mode'))

        parser = WordfenceParser()
        parser.run(args.single_url, None, args.overwrite, args.force, args.overwrite_enhanced)

    logger.info('Done. Took %s', time.strftime("%H:%M:%S", time.gmtime(time.time() - ts)))


if __name__ == '__main__':
    main()
