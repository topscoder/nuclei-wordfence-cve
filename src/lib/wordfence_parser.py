from lib.colors import red, green, yellow
from lib.logger import logger
from lxml import html
import hashlib
import os
import requests
import re
from lib.parser_interface import ParserInterface


class WordfenceParser(ParserInterface):

    url = None
    html_content = None

    def run(self, url, outputfile=None, overwrite=False, force=False, overwrite_enhanced=False) -> bool:
        """Execute the Wordfence Parser.

        Args:
            url (string): URL of the Wordfence page to parse.
            outputfile (string, optional): Target filename to write the generated template to. Defaults to None.
            overwrite (bool, optional): Whether or not to overwrite the template if it already exists. Defaults to False.
            force (bool, optional): Whether or not to regenerate the template if it already exists. Defaults to False.

        Returns:
            bool: Template generated
        """
        if url is None or url.strip() == "":
            return False

        url = url.strip()
        self.url = url

        try:
            page = requests.get(url)
        except Exception:
            logger.warning(red(f"[*] Whoops, Failed to open URL: {url}"))
            return False

        if page.status_code > 400:
            logger.warning(red(f"[*] [HTTP {page.status_code}] Could not read URL: ${url}$"))
            return False

        self.html_content = html.fromstring(page.content)
        title = self.read_title(self.html_content)
        description = self.read_description(self.html_content)
        cve_id = self.read_cve_id(self.html_content)

        software_type = self.get_software_type(self.html_content)
        if software_type is False:
            return False

        object_slug = self.get_object_slug(self.html_content)
        if object_slug is False:
            return False

        object_category_slug = self.get_object_category_slug(software_type)

        target_filename = self.get_target_filename(cve_id, outputfile, object_slug)
        logger.debug(f"[ ] Target filename: {target_filename}")

        template_id = self.get_template_id(cve_id, outputfile, object_slug)

        # determine file path
        year = ""
        if cve_id != "":
            cve_parts = cve_id.split('-')
            year = cve_parts[1]
            filepath = f'nuclei-templates/{year}/{target_filename}'
        else:
            filepath = f'nuclei-templates/cve-less/{object_category_slug}/{target_filename}'

        # Check to see if there is already a template for this cve in our local templates repo
        if overwrite is False:
            if os.path.isfile(f"{filepath}"):
                logger.info(yellow(f"[*] Note: There is already a template for this cve in our local nuclei-templates repo: {filepath}"))
                logger.info(yellow("[*] Skipping. Use --overwrite if you want to ignore this and overwrite the template."))
                return False

        # Check to see if there is already a template for this cve in the nuclei-templates repo
        if force is False and year != "":
            check_page = requests.get(
                f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/{target_filename}")

            if check_page.status_code == 200:
                logger.info(yellow("[*] Note: There is already a template for this cve in the nuclei-templates repo."))
                logger.info(yellow(f"[*] https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/{target_filename}"))
                logger.info(yellow("[*] Skipping. Use --force if you want to ignore this and create a new template."))
                return False

        # Manually enhanced templates can be marked with "# Enhanced" in last line of the template.
        # This ensures the template is overwritten only after using the --overwrite-enhanced flag.
        if os.path.isfile(f"{filepath}"):
            with open(f"{filepath}", "r") as fp:
                lines = fp.readlines()
                for line in lines:
                    if line.find("# Enhanced") == 0:
                        logger.info(yellow(f"[*] Note: There is already an **enhanced** template in our local nuclei-templates repo: {filepath}"))
                        logger.info(yellow("[*] Skipping. Use --overwrite-enhanced if you want to ignore this and overwrite the template."))
                        return False

        # Validate "SOFTWARE_TYPE"
        if software_type != "Plugin" and software_type != "Theme" and software_type != "Core":
            logger.warning(red(f"[*] Skipping. Software type {software_type} is not supported."))
            # TODO could be a page with a vuln which affects more plugins/themes
            # like https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/fuse-social-floating-sidebar/appsero-121-missing-authorization
            return False

        cvss_score = self.get_cvss_score(self.html_content)
        cvss_rating = self.get_cvss_rating(cvss_score)
        reference_list = self.get_references(self.html_content)
        cvss_vector = self.get_cvss_vector(self.html_content)
        object_category_tag = self.get_object_category_tag(software_type)
        find_file = self.find_version_in_file(software_type)
        version_regex = self.get_version_regex(software_type)

        try:
            affected_version = self.get_affected_version(self.html_content)
            logger.info(f'affected_version={affected_version}')
        except Exception as e:
            logger.warning(e)
            return False

        # Parse template
        tpl = self.get_template_filename(software_type)
        with open(tpl) as template:
            template_content = template.read()
            template_content = template_content.replace('__TEMPLATE_ID__', str(template_id))
            template_content = template_content.replace('__CVE_ID__', cve_id.strip())
            template_content = template_content.replace('__CVE_NAME__', title.strip())
            template_content = template_content.replace('__CVE_SEVERITY__', cvss_rating.strip().lower())
            template_content = template_content.replace('__CVE_DESCRIPTION__', description.strip())
            template_content = template_content.replace('__CVE_REFERENCES__', "\n    ".join(reference_list))
            template_content = template_content.replace('__CVSS_VECTOR__', cvss_vector.strip())
            template_content = template_content.replace('__CVSS_SCORE__', str(cvss_score))
            template_content = template_content.replace('__OBJECT_CATEGORY_SLUG__', object_category_slug)
            template_content = template_content.replace('__OBJECT_CATEGORY_TAG__', object_category_tag)
            template_content = template_content.replace('__FIND_FILE__', find_file)
            template_content = template_content.replace('__VERSION_REGEX__', version_regex)
            template_content = template_content.replace('__OBJECT_SLUG__', object_slug.strip())
            template_content = template_content.replace('__VERSION_COMPARE__', f"{affected_version}")

            logger.debug(f'target_filename={target_filename}')

            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w+') as target:
                target.write(template_content)
                logger.info(green("[>] " + filepath))

        return True

    def read_title(self, content):
        title = content.xpath('//h1/text()')[0]
        logger.info(f"[ ] Title: {title}")
        return title

    def read_description(self, content):
        # Read "DESCRIPTION"
        desc = content.xpath(
            '/html/body/div[1]/section[3]/div/div/div[2]/div/div/p/text()')
        if len(desc) == 0:
            logger.warning(red(f"[*] Whoops. No description found. Are you sure this is a valid CVE page? {self.url}"))
            # TODO could be a plugin page containing multiple vulnerabilities
            # like https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/brandfolder
            return False

        description = desc[0].replace('"', "'").replace("\\", "/")
        return description

    def read_cve_id(self, content):
        # Read "CVE_ID"
        cve_ids = content.xpath('//table/tbody/tr/td/a[contains(@href, "cve")]/text()')
        cve_id = cve_ids[0].strip() if len(cve_ids) > 0 else ""
        return cve_id

    def get_uniq_id(self, url):
        md5 = hashlib.md5(url.encode())
        return md5.hexdigest()

    def get_target_filename(self, cve_id, outputfile, object_slug):
        return self.get_template_id(cve_id, outputfile, object_slug) + ".yaml"

    def get_template_id(self, cve_id, outputfile, object_slug):
        # Create "TEMPLATE_ID"
        if outputfile != "" and outputfile is not None and outputfile != "None":
            return outputfile.replace(".yaml", "")

        if cve_id != "":
            logger.debug(f"[ ] CVE ID: {cve_id}")
            return cve_id

        unique_id = self.get_uniq_id(self.url)
        object_slug = object_slug.lower()

        logger.debug(f"[ ] No CVE ID. Created new unique ID: {unique_id}")
        return f"{object_slug}-{unique_id}"

    def get_cvss_vector(self, content):
        # Read "CVSS_VECTOR"
        try:
            cvss_vector_xp = content.xpath(
                '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[2]/div[2]/a/text()')

            if len(cvss_vector_xp) == 0:
                raise

            cvss_vector = cvss_vector_xp[0].strip()
        except Exception:
            cvss_vector = ""

        logger.debug(f"[ ] CVSS Vector: {cvss_vector}")

        return cvss_vector

    def get_cvss_score(self, content):
        # Read "CVSS_SCORE"
        try:
            cvss_score_xp = content.xpath(
                '/html/body/div[1]/section[3]/div/div/div[1]/div/div/div/div[1]/div/span/text()')

            if len(cvss_score_xp) == 0:
                raise

            cvss_score = float(cvss_score_xp[0].strip())
        except Exception:
            cvss_score = ""

        logger.debug(f"[ ] CVSS Score: {cvss_score}")

        return cvss_score

    def get_cvss_rating(self, cvss_score):
        # Determine "CVSS_RATING"
        # In compliance with docs: https://github.com/projectdiscovery/nuclei/blob/main/SYNTAX-REFERENCE.md#severityholder
        cvss_rating = "unknown" if cvss_score == "" \
            else "Low" if cvss_score < 4 \
            else "Medium" if cvss_score < 7 \
            else "High" if cvss_score < 9 \
            else "Critical" if cvss_score <= 10 \
            else "unknown"

        logger.debug(f"[ ] CVSS Rating: {cvss_rating}")

        return cvss_rating

    def get_software_type(self, content):
        # Read "SOFTWARE_TYPE"
        software_type = content.xpath(
            '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[1]/td/text()')

        if len(software_type) == 0:
            logger.warning(red("[*] Skipping. No software type was found."))
            return False

        software_type = software_type[0].strip()
        logger.debug(f"[ ] Software Type: {software_type}")
        return software_type

    def get_object_slug(self, content):
        # Read "OBJECT_SLUG"
        object_slug_xp = content.xpath(
            '/html/body/div[1]/section[5]/div/div[1]/div/div/div[2]/table/tbody/tr[2]/td/text()')

        if len(object_slug_xp) == 0:
            logger.warning(red("[*] Skipping. No object slug found."))
            return False

        object_slug = object_slug_xp[0].strip()

        logger.debug(f"[ ] Plugin slug: {object_slug}")

        return object_slug

    def get_object_category_slug(self, software_type):
        return "themes" if software_type == "Theme" else "core" if software_type == "Core" else "plugins"

    def get_object_category_tag(self, software_type):
        return "wp-theme" if software_type == "Theme" else "wp-core" if software_type == "Core" else "wp-plugin"

    def get_references(self, content):
        # Read "REFERENCES"
        references = content.xpath('//*[@id="app-wrapper"]//h4[text()="References"]/following-sibling::ul/li/a')

        reference_list = []
        for ref in references:
            reference_list.append("- " + ref.attrib['href'])

        # logger.debug(reference_list)

        return reference_list

    def get_affected_version(self, content) -> str:
        # Read "AFFECTED_VERSION"
        affected_version_xp = content.xpath('//*[@id="app-wrapper"]//th[text()="Affected Version"]/following-sibling::td//li/text()')

        logger.debug(f'affected_version={affected_version_xp}')

        if len(affected_version_xp) == 0:
            affected_version_xp = content.xpath('//*[@id="app-wrapper"]//th[text()="Affected Versions"]/following-sibling::td//li/text()')
            logger.debug(f'affected_versions={affected_version_xp}')

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
                affected_version = f"'>= {m.group(2)}', '<= {m.group(4)}'"
            else:
                if str(affected_version).lower().find("all") > -1:
                    affected_version = "'>0'"
                else:
                    affected_version = f"'{affected_version}'"

        logger.debug(f"[ ] Affected version: {affected_version}")

        return affected_version

    def find_version_in_file(self, software_type):
        object_slug = self.get_object_slug(self.html_content)
        if software_type == "Theme":
            filepath = f"wp-content/themes/{object_slug}/style.css"
        elif software_type == "Core":
            filepath = "index.php"
        else:
            filepath = f"wp-content/plugins/{object_slug}/readme.txt"

        return filepath

    def get_version_regex(self, software_type):
        if software_type == "Theme":
            regex = "(?mi)Version: ([0-9.]+)"
        elif software_type == "Core":
            regex = "(?mi)\?v=([0-9.]+)"
        else:
            regex = "(?mi)Stable tag: ([0-9.]+)"

        return regex

    def get_template_filename(self, software_type):
        if software_type == "core":
            return 'lib/template-wp-core.yaml.template'

        return 'lib/template-main.yaml.template'
