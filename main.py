# Usage:
# python3 main.py
#   --url https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/tenweb-speed-optimizer/10web-booster-website-speed-optimization-cache-page-speed-optimizer-21344-missing-authorization-in-settings-import-to-stored-cross-site-scripting
#   --output cve-1234-09876.yaml

from lxml import html
import argparse
import os
import requests
import random

parser = argparse.ArgumentParser(description='Process a Wordfence CVE report')
parser.add_argument('--url', required=True, help='the URL of the Wordfence CVE report. eg https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/houzez-login-register/houzez-login-register-263-privilege-escalation')
parser.add_argument('--output', required=False, help='the output filename to store the nuclei-template in', default="")
parser.add_argument('--force', required=False, help='ignore if there is already a template in the nuclei-templates repo', default=False, action='store_true')
parser.add_argument('--overwrite', required=False, help='ignore if there is already a template in our local nuclei-templates repo', default=False, action='store_true')
args = parser.parse_args()

try:
    page = requests.get(args.url)
except:
    print(f"Whoops, URL niet bereikbaar.")
    exit(1)

content = html.fromstring(page.content)

title = content.xpath('//h1/text()')[0]
print(f"[ ] Title: {title}")
description = content.xpath('/html/body/div[1]/section[3]/div/div/div[2]/div/div/p/text()')[0]

cve_ids = content.xpath('//table/tbody/tr/td/a[contains(@href, "cve")]/text()')
cve_id = cve_ids[0].strip() if len(cve_ids) > 0 else ""
print(f"[ ] CVE ID: {cve_id}")

if args.output != "" and args.output != "None":
    target_filename = args.output
else:
    if cve_id == "":
        print(f"[*] Whoops. No CVE ID found and neither a filename passed.")
        exit(1)
    else:
        target_filename = f"{cve_id}.yaml"

print(f"[ ] Target filename: {target_filename}")

if cve_id != "":
    cve_parts = cve_id.split('-')
    year = cve_parts[1]

    # Check to see if there is already a template for this cve in our local templates repo
    if os.path.isfile("nuclei-templates/CVE-2022-0234.yaml"):
        print(
            f"[*] Note: There is already a template for this cve in our local nuclei-templates repo.")
        print(f"[*] ./nuclei-templates/CVE-2022-0234.yaml")
        if args.overwrite is not True:
            print(
                f"[*] Exiting. Use --overwrite if you want to ignore this and overwrite the template.")
            exit(1)

    # Check to see if there is already a template for this cve in the nuclei-templates repo
    check_page = requests.get(
        f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/CVE-{year}-{cve_parts[2]}.yaml")

    if check_page.status_code == 200:
        print(f"[*] Note: There is already a template for this cve in the nuclei-templates repo.")
        print(
            f"[*] https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/CVE-{year}-{cve_parts[2]}.yaml")
        if args.force is not True:
            print(f"[*] Exiting. Use --force if you want to ignore this and create a new template.")
            exit(1)

template_id = cve_id if cve_id != "" else "random-id-" + str(random.randint(0,10000))

cvss_vector = content.xpath(
    '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[2]/div[2]/a/text()')[0].strip()

print(f"[ ] CVSS Vector: {cvss_vector}")

cvss_score = content.xpath(
    '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[1]/div/span/text()')[0].strip()

cvss_score = float(cvss_score)

print(f"[ ] CVSS Score: {cvss_score}")

cvss_rating = "Low" if cvss_score < 4 \
    else "Medium" if cvss_score < 7 \
    else "High" if cvss_score < 9 \
    else "Critical" if cvss_score <= 10 \
    else "invalid cvss score"

print(f"[ ] CVSS Rating: {cvss_rating}")

software_type = content.xpath(
    '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[1]/td/text()')[0].strip()

print(f"[ ] Software Type: {software_type}")

# software_type should be Plugin
if software_type != "Plugin" and software_type != "Theme":
    print(f"[*] Exiting. Software type {software_type} is not supported.")
    exit(1)

object_category_slug = "themes" if software_type == "Theme" else "plugins"
object_category_tag = "wp-theme" if software_type == "Theme" else "wp-plugin"

object_slug = content.xpath(
    '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[2]/td/text()')[0].strip()

print(f"[ ] Plugin slug: {object_slug}")

references = content.xpath(
    '/html/body/div[1]/section[3]/div/div/div[2]/div/div/ul/li/a')

reference_list = []
for ref in references:
    reference_list.append("- " + ref.attrib['href'])

affected_version = content.xpath(
    '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[5]/td/ul/li/text()')[0]

print(f"[ ] Affected version: {affected_version}")

with open('template.yaml') as template:
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
        print("[>] ./nuclei-templates/" + target_filename)
