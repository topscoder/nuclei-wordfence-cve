# Usage:
# python3 main.py
#   --url https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/tenweb-speed-optimizer/10web-booster-website-speed-optimization-cache-page-speed-optimizer-21344-missing-authorization-in-settings-import-to-stored-cross-site-scripting
#   --output cve-1234-09876.yaml

# drop in folder based on cve year
# add references
# fix severity
# implement arguments (url, output)
# check if cve template not already exists
#    eg. https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/2002/CVE-2002-1131.yaml

from lxml import html
import argparse
import requests

parser = argparse.ArgumentParser(description='Process a Wordfence CVE report')
parser.add_argument('--url', required=True, help='the URL of the Wordfence CVE report. eg https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/houzez-login-register/houzez-login-register-263-privilege-escalation')
parser.add_argument('--output', required=False, help='the output filename to store the nuclei-template in', default="")
args = parser.parse_args()

try:
    page = requests.get(args.url)
except:
    print(f"Whoops, URL niet bereikbaar.")
    exit(1)

content = html.fromstring(page.content)

title = content.xpath('//h1/text()')[0]
description = content.xpath('/html/body/div[1]/section[3]/div/div/div[2]/div/div/p/text()')[0]

cve_ids = content.xpath('//table/tbody/tr/td/a[contains(@href, "cve")]/text()')
cve_id = cve_ids[0] if len(cve_ids) > 0 else ""

if args.output != "" and args.output != "None":
    target_filename = args.output
else:
    if cve_id == "":
        print(f"Whoops. No CVE ID found and neither a filename passed.")
        exit(1)
    else:
        target_filename = f"{cve_id}.yaml" 

cvss_vector = content.xpath(
    '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[2]/div[2]/a/text()')[0]

cvss_score = content.xpath(
    '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[1]/div/span/text()')[0]

cvss_rating = content.xpath(
    '//td[contains(@class, "cvss-rating")]/text()')[0]

software_type = content.xpath(
    '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[1]/td/text()')[0]

# software_type should be Plugin
if software_type.strip() != "Plugin":
    print(f"Software type {software_type} is not supported.")
    exit(1)

plugin_slug = content.xpath(
    '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[2]/td/text()')[0]

references = content.xpath(
    '/html/body/div[1]/section[3]/div/div/div[2]/div/div/ul/li/a')

# FIXME
# for ref in references:
    # print(ref.attrib['href'])

affected_version = content.xpath(
    '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[5]/td/ul/li/text()')[0]

# print(cvss_score)
with open('template.yaml') as template:
    template_content = template.read()
    template_content = template_content.replace('__CVE_ID__', cve_id.strip())
    template_content = template_content.replace('__CVE_NAME__', title.strip())
    template_content = template_content.replace(
        '__CVE_SEVERITY__', cvss_rating.strip())
    template_content = template_content.replace('__CVE_DESCRIPTION__', description.strip())
    # template_content = template_content.replace(
        # '__CVE_REFERENCES__', description)
    template_content = template_content.replace('__CVSS_VECTOR__', cvss_vector.strip())
    template_content = template_content.replace('__CVSS_SCORE__', cvss_score.strip())
    template_content = template_content.replace('__PLUGIN_SLUG__', plugin_slug.strip())
    template_content = template_content.replace(
        '__VERSION_COMPARE__', affected_version.strip())

    with open(target_filename, 'w+') as target:
        target.write(template_content)
        print(target_filename)
