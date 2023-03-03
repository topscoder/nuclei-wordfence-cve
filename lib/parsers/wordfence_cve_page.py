from lib.colors import red, green, yellow
from lib.logger import logger
from lxml import html
import os
import requests
import random
import re

def wordfence_cve_page(url, outputfile = None, overwrite = False, force = False):
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

    # Read "DESCRIPTION"
    desc = content.xpath(
        '/html/body/div[1]/section[3]/div/div/div[2]/div/div/p/text()')
    if len(desc) == 0:
        logger.warning(red(f"[*] Whoops. No description found. Are you sure this is a valid CVE page? ${url}$"))
        return False

    description = desc[0].replace('"', "'").replace("\\", "/")

    # Read "TITLE"
    title = content.xpath('//h1/text()')[0]

    logger.info(f"[ ] Title: {title}")

    # Read "CVE_ID"
    cve_ids = content.xpath('//table/tbody/tr/td/a[contains(@href, "cve")]/text()')
    cve_id = cve_ids[0].strip() if len(cve_ids) > 0 else ""
    year = ""

    if outputfile != "" and outputfile != "None":
        target_filename = outputfile
    else:
        if cve_id == "":
            logger.warning(red(f"[*] Whoops. No CVE ID found nor a filename was passed."))
            return False
        else:
            target_filename = f"{cve_id}.yaml"

    logger.info(f"[ ] CVE ID: {cve_id}")

    if cve_id != "":
        cve_parts = cve_id.split('-')
        year = cve_parts[1]

        # Check to see if there is already a template for this cve in our local templates repo
        if overwrite is False:
            if os.path.isfile(f"nuclei-templates/{year}/CVE-{year}-{cve_parts[2]}.yaml"):
                logger.info(yellow(f"[*] Note: There is already a template for this cve in our local nuclei-templates repo."))
                logger.info(
                    yellow(f"[*] ./nuclei-templates/{year}/CVE-{year}-{cve_parts[2]}.yaml"))
                logger.info(yellow(f"[*] Exiting. Use --overwrite if you want to ignore this and overwrite the template."))
                return False

        # Check to see if there is already a template for this cve in the nuclei-templates repo
        if force is False:
            check_page = requests.get(
                f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/CVE-{year}-{cve_parts[2]}.yaml")

            if check_page.status_code == 200:
                logger.info(yellow(f"[*] Note: There is already a template for this cve in the nuclei-templates repo."))
                logger.info(yellow(f"[*] https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/CVE-{year}-{cve_parts[2]}.yaml"))
                logger.info(yellow(f"[*] Exiting. Use --force if you want to ignore this and create a new template."))
                return False

    logger.info(f"[ ] Target filename: {target_filename}")

    # Create "TEMPLATE_ID"
    template_id = cve_id if cve_id != "" else "random-id-" + str(random.randint(0,10000))

    # Read "CVSS_VECTOR"
    try:
        cvss_vector_xp = content.xpath(
            '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[2]/div[2]/a/text()')

        if len(cvss_vector_xp) == 0:
            raise

        cvss_vector = cvss_vector_xp[0].strip()
    except:
        cvss_vector = ""

    logger.info(f"[ ] CVSS Vector: {cvss_vector}")

    # Read "CVSS_SCORE"
    try:
        cvss_score_xp = content.xpath(
            '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[1]/div/span/text()')

        if len(cvss_score_xp) == 0:
            raise

        cvss_score = float(cvss_score_xp[0].strip())
    except:
        cvss_score = ""

    logger.info(f"[ ] CVSS Score: {cvss_score}")

    # Determine "CVSS_RATING"
    cvss_rating = "" if cvss_score == "" \
        else "Low" if cvss_score < 4 \
        else "Medium" if cvss_score < 7 \
        else "High" if cvss_score < 9 \
        else "Critical" if cvss_score <= 10 \
        else "invalid cvss score"

    logger.info(f"[ ] CVSS Rating: {cvss_rating}")

    # Read "SOFTWARE_TYPE"
    software_type = content.xpath(
        '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[1]/td/text()')

    if len(software_type) == 0:
        logger.warning(red(f"[*] Exiting. No software type was found."))
        return False

    software_type = software_type[0].strip()
    logger.info(f"[ ] Software Type: {software_type}")

    # Validate "SOFTWARE_TYPE"
    if software_type != "Plugin" and software_type != "Theme":
        logger.warning(red(f"[*] Exiting. Software type {software_type} is not supported."))
        return False

    object_category_slug = "themes" if software_type == "Theme" else "plugins"
    object_category_tag = "wp-theme" if software_type == "Theme" else "wp-plugin"
    find_file = "style.css" if software_type == "Theme" else "readme.txt"
    version_tag = "Version" if software_type == "Theme" else "Stable tag"

    # Read "OBJECT_SLUG"
    object_slug_xp = content.xpath(
        '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[2]/td/text()')

    if len(object_slug_xp) == 0:
        logger.warning(red(f"[*] Exiting. No object slug found."))
        return False

    object_slug = object_slug_xp[0].strip()

    logger.info(f"[ ] Plugin slug: {object_slug}")

    # Read "REFERENCES"
    references = content.xpath(
        '/html/body/div[1]/section[3]/div/div/div[2]/div/div/ul/li/a')

    reference_list = []
    for ref in references:
        reference_list.append("- " + ref.attrib['href'])

    # Read "AFFECTED_VERSION"
    affected_version_xp = content.xpath(
        '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[5]/td/ul/li/text()')

    if len(affected_version_xp) == 0:
        affected_version = ""
    else:
        affected_version = affected_version_xp[0].strip()
        # <= 0.2.35
        # < 0.2.35
        # 0.2.35
        # 0.2.35 - 0.4.3
        # all
        # *
        m = re.match("(.*?)([0-9.-]+)(\s?-\s?)([0-9.-]+)(.*?)", affected_version)
        if m and m.groups():
            affected_version = f"'=>{m.group(2)}', '<={m.group(4)}'"
        else:
            if str(affected_version).lower().find("all") > -1:
                affected_version = f"'>0'"
            else:
                affected_version = f"'{affected_version}'"

    logger.info(f"[ ] Affected version: {affected_version}")

    # Parse template
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
        template_content = template_content.replace('__FIND_FILE__', find_file)
        template_content = template_content.replace('__VERSION_TAG__', version_tag)
        template_content = template_content.replace(
            '__OBJECT_SLUG__', object_slug.strip())
        template_content = template_content.replace(
            '__VERSION_COMPARE__', f"{affected_version}")

        filepath = os.path.join("nuclei-templates", year, target_filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w+') as target:
            target.write(template_content)
            logger.info(green("[>] " + filepath))