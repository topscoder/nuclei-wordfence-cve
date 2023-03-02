# Usage:
# python3 main.py
#   --url https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/tenweb-speed-optimizer/10web-booster-website-speed-optimization-cache-page-speed-optimizer-21344-missing-authorization-in-settings-import-to-stored-cross-site-scripting
#   --outputfile cve-1234-09876.yaml
#
# TODO: Fix parser for multiple themes (https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes/wallstreet/multiple-themes-various-versions-reflected-cross-site-scripting)
# TODO: Implement wordpress core vulnerabilities (https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-401-hash-collision)

from lib.colors import red, green, yellow
from lxml import html
from queue import Queue
from threading import Thread
from time import time
import argparse
import logging
import os
import requests
import random


parser = argparse.ArgumentParser(description='Process a Wordfence CVE report')
parser.add_argument('--inputfile', required=False, help='file containing Urls to Wordfence CVE reports')
parser.add_argument('--url', required=False, help='the URL of the Wordfence CVE report. eg https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/houzez-login-register/houzez-login-register-263-privilege-escalation')
parser.add_argument('--outputfile', required=False, help='the output filename to store the nuclei-template in', default="")
parser.add_argument('--force', required=False, help='ignore if there is already a template in the official nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--overwrite', required=False, help='ignore if there is already a template in our local nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--threads', required=False, help='boost by increasing the default worker threads (default 2)', default=2, type=int)
args = parser.parse_args()


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

WORKER_THREADS = int(args.threads)
logger.info(f"Setting threads to {WORKER_THREADS}")


class DownloadWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            url = self.queue.get()
            try:
                process_wordfence_url(url)
            finally:
                self.queue.task_done()



def process_wordfence_url(url):
    if url is None or url.strip() == "":
        return False

    url = url.strip()

    try:
        page = requests.get(url)
    except:
        logger.warning(red(f"[*] Whoops, Failed to open URL: {url}"))
        return False
    
    if page.status_code > 400:
        logger.warning(red(f"[*] [HTTP {page.status_code}] Could not read URL: ${url}$"))
        return False

    content = html.fromstring(page.content)

    desc = content.xpath(
        '/html/body/div[1]/section[3]/div/div/div[2]/div/div/p/text()')
    if len(desc) == 0:
        logger.warning(red(f"[*] Whoops. No description found. Are you sure this is a valid CVE page? ${url}$"))
        return False

    description = desc[0]

    title = content.xpath('//h1/text()')[0]

    logger.info(f"[ ] Title: {title}")

    cve_ids = content.xpath('//table/tbody/tr/td/a[contains(@href, "cve")]/text()')
    cve_id = cve_ids[0].strip() if len(cve_ids) > 0 else ""
    logger.info(f"[ ] CVE ID: {cve_id}")

    if args.outputfile != "" and args.outputfile != "None":
        target_filename = args.outputfile
    else:
        if cve_id == "":
            logger.warning(red(f"[*] Whoops. No CVE ID found nor a filename was passed."))
            return False
        else:
            target_filename = f"{cve_id}.yaml"

    logger.info(f"[ ] Target filename: {target_filename}")

    if cve_id != "":
        cve_parts = cve_id.split('-')
        year = cve_parts[1]

        # Check to see if there is already a template for this cve in our local templates repo
        if os.path.isfile(f"nuclei-templates/CVE-{year}-{cve_parts[2]}.yaml"):
            logger.info(yellow(f"[*] Note: There is already a template for this cve in our local nuclei-templates repo."))
            logger.info(yellow(f"[*] ./nuclei-templates/CVE-{year}-{cve_parts[2]}.yaml"))

            if args.overwrite is not True:
                logger.info(yellow(f"[*] Exiting. Use --overwrite if you want to ignore this and overwrite the template."))
                return False

        # Check to see if there is already a template for this cve in the nuclei-templates repo
        check_page = requests.get(
            f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/CVE-{year}-{cve_parts[2]}.yaml")

        if check_page.status_code == 200:
            logger.info(yellow(f"[*] Note: There is already a template for this cve in the nuclei-templates repo."))
            logger.info(yellow(f"[*] https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/CVE-{year}-{cve_parts[2]}.yaml"))

            if args.force is not True:
                logger.info(yellow(f"[*] Exiting. Use --force if you want to ignore this and create a new template."))
                return False

    template_id = cve_id if cve_id != "" else "random-id-" + str(random.randint(0,10000))

    cvss_vector = content.xpath(
        '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[2]/div[2]/a/text()')[0].strip()

    logger.info(f"[ ] CVSS Vector: {cvss_vector}")

    cvss_score = content.xpath(
        '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[1]/div/span/text()')[0].strip()

    cvss_score = float(cvss_score)

    logger.info(f"[ ] CVSS Score: {cvss_score}")

    cvss_rating = "Low" if cvss_score < 4 \
        else "Medium" if cvss_score < 7 \
        else "High" if cvss_score < 9 \
        else "Critical" if cvss_score <= 10 \
        else "invalid cvss score"

    logger.info(f"[ ] CVSS Rating: {cvss_rating}")

    software_type = content.xpath(
        '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[1]/td/text()')[0].strip()

    logger.info(f"[ ] Software Type: {software_type}")

    # software_type should be Plugin
    if software_type != "Plugin" and software_type != "Theme":
        logger.warning(red(f"[*] Exiting. Software type {software_type} is not supported."))
        return False

    object_category_slug = "themes" if software_type == "Theme" else "plugins"
    object_category_tag = "wp-theme" if software_type == "Theme" else "wp-plugin"

    object_slug = content.xpath(
        '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[2]/td/text()')[0].strip()

    logger.info(f"[ ] Plugin slug: {object_slug}")

    references = content.xpath(
        '/html/body/div[1]/section[3]/div/div/div[2]/div/div/ul/li/a')

    reference_list = []
    for ref in references:
        reference_list.append("- " + ref.attrib['href'])

    affected_version = content.xpath(
        '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[5]/td/ul/li/text()')[0]

    logger.info(f"[ ] Affected version: {affected_version}")

    with open('lib/template.yaml') as template:
        template_content = template.read()
        template_content = template_content.replace(
            '__TEMPLATE_ID__', str(template_id))
        template_content = template_content.replace('__CVE_ID__', cve_id.strip())
        template_content = template_content.replace('__CVE_NAME__', title.strip())
        template_content = template_content.replace(
            '__CVE_SEVERITY__', cvss_rating.strip())
        template_content = template_content.replace('__CVE_DESCRIPTION__', description.strip())
        template_content = template_content.replace(
            '__CVE_REFERENCES__', "\n    ".join(reference_list))
        template_content = template_content.replace('__CVSS_VECTOR__', cvss_vector.strip())
        template_content = template_content.replace('__CVSS_SCORE__', str(cvss_score))
        template_content = template_content.replace('__OBJECT_CATEGORY_SLUG__', object_category_slug)
        template_content = template_content.replace('__OBJECT_CATEGORY_TAG__', object_category_tag)
        template_content = template_content.replace(
            '__OBJECT_SLUG__', object_slug.strip())
        template_content = template_content.replace(
            '__VERSION_COMPARE__', affected_version.strip())

        with open("nuclei-templates/" + target_filename, 'w+') as target:
            target.write(template_content)
            logger.info(green("[>] ./nuclei-templates/" + target_filename))


def main():
    ts = time()
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
        queue.put(url)
    
    queue.join()
    logging.info('Done. Took %s', time() - ts)


if __name__ == '__main__':
    main()
    