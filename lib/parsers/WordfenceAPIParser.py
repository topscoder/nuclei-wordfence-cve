from lib.colors import red, green, yellow
from lib.logger import logger
from lxml import html
import hashlib
import json
import os
import requests
import re

from lib.parsers.ParserInterface import ParserInterface


class WordfenceAPIParser(ParserInterface):
    
    url = None
    html_content = None

    def run(self, url, overwrite = False, force = False, overwrite_enhanced = False) -> bool:
        """Execute the Wordfence API Parser.

        Args:
            url (string): URL of the Wordfence page to parse.
            overwrite (bool, optional): Whether or not to overwrite the template if it already exists. Defaults to False.
            force (bool, optional): Whether or not to regenerate the template if it already exists. Defaults to False.

        Returns:
            bool: Template generated
        """
        local_json_testing_mode = False

        if local_json_testing_mode is True:
            file_path = "./vulnerabilities.production.json"
            with open(file_path, "r") as file:
                vulnerabilities = json.load(file)
                
                # Print the vulnerabilities
                for vulnerability_id, vulnerability in vulnerabilities.items():
                    self.process_item(vulnerability, overwrite, force, overwrite_enhanced)

        if local_json_testing_mode is False:
            if url is None or url.strip() == "":
                return False

            url = url.strip()

            # try:
            response = requests.get(url)

            # Check the response status code
            if response.status_code == 200:
                # The request was successful, so parse the JSON response
                vulnerabilities = response.json()
        
                # Print the vulnerabilities
                for vulnerability_id, vulnerability in vulnerabilities.items():
                    self.process_item(vulnerability, overwrite, force, overwrite_enhanced)
            
            if response.status_code > 400:
                logger.warning(red(f"[*] [HTTP {response.status_code}] Could not read URL: ${url}$"))
                return False
        
    def process_item(self, json_object, overwrite, force, overwrite_enhanced):
        title = json_object.get('title')
        description = json_object.get('description')
        cve_id = json_object.get('cve')
        if cve_id is None:
            cve_id = ""
        
        software = json_object.get('software', [])
        if software:
            for item in software:
                software_type = item.get('type')
                software_slug = item.get('slug')
        
                object_category_slug = "plugins" if software_type == 'plugin' else 'unknown'

                template_id = self.get_template_id(cve_id, item)

                target_filename = template_id + ".yaml" 
                logger.info(f"[ ] Target filename: {target_filename}")

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
                        logger.info(yellow(f"[*] Skipping. Use --overwrite if you want to ignore this and overwrite the template."))
                        return False

                # Check to see if there is already a template for this cve in the nuclei-templates repo
                if force is False and year != "":
                    check_page = requests.get(
                        f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/{target_filename}")

                    if check_page.status_code == 200:
                        logger.info(yellow(f"[*] Note: There is already an official template for this CVE in the nuclei-templates repo."))
                        logger.info(yellow(f"[*] https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/{year}/{target_filename}"))
                        logger.info(yellow(f"[*] Skipping. Use --force if you want to ignore this and create a new template."))
                        return False
                
                 # Manually enhanced templates can be marked with "# Enhanced" in last line of the template.
                
                # This ensures the template is overwritten only after using the --overwrite-enhanced flag.
                if os.path.isfile(f"{filepath}"):
                    with open(f"{filepath}", "r") as fp:
                        lines = fp.readlines()
                        for line in lines:
                            if line.find("# Enhanced") == 0:
                                logger.info(yellow(f"[*] Note: There is already an **enhanced** template in our local nuclei-templates repo: {filepath}"))
                                logger.info(yellow(f"[*] Skipping. Use --overwrite-enhanced if you want to ignore this and overwrite the template."))
                                return False
                            
                if self.type_is_supported(software_type) is False:
                    logger.warning(red(f"[*] Skipping. Software type {software_type} is not supported."))
                    # TODO could be a page with a vuln which affects more plugins/themes
                    # like https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/fuse-social-floating-sidebar/appsero-121-missing-authorization
                    return False

                try:
                    cvss_score = json_object.get('cvss')['score']
                    cvss_rating = json_object.get('cvss')['rating']
                    cvss_vector = json_object.get('cvss')['vector']
                except:
                    cvss_score = ""
                    cvss_rating = ""
                    cvss_vector = ""

                if cvss_rating == "":
                    cvss_rating = self.determine_severity(title)

                reference_list = json_object.get('references', {})
                
                object_category_tag = self.get_object_category_tag(software_type)
                find_file = self.target_version_file(software_type, item)
                version_regex = self.get_version_regex(software_type)

                affected_versions = item.get('affected_versions')
                for version_range, version_data in affected_versions.items():
                    affected_version = self.get_affected_version(version_data)
                
                # Parse template
                tpl = self.get_template_filename(software_type)
                with open(tpl) as template:
                    template_content = template.read()
                    template_content = template_content.replace('__TEMPLATE_ID__', str(template_id))
                    template_content = template_content.replace('__CVE_ID__', cve_id.strip())
                    template_content = template_content.replace('__CVE_NAME__', title.strip())
                    template_content = template_content.replace('__CVE_SEVERITY__', cvss_rating.strip().lower())
                    template_content = template_content.replace('__CVE_DESCRIPTION__', description.strip())
                    template_content = template_content.replace('__CVE_REFERENCES__', "\n    - ".join(reference_list))
                    template_content = template_content.replace('__CVSS_VECTOR__', cvss_vector.strip())
                    template_content = template_content.replace('__CVSS_SCORE__', str(cvss_score))
                    template_content = template_content.replace('__OBJECT_CATEGORY_SLUG__', object_category_slug)
                    template_content = template_content.replace('__OBJECT_CATEGORY_TAG__', object_category_tag)
                    template_content = template_content.replace('__FIND_FILE__', find_file)
                    template_content = template_content.replace('__VERSION_REGEX__', version_regex)
                    template_content = template_content.replace('__OBJECT_SLUG__', software_slug.strip())
                    template_content = template_content.replace('__VERSION_COMPARE__', f"{affected_version}")

                    logger.debug(f'target_filename={target_filename}')

                    os.makedirs(os.path.dirname(filepath), exist_ok=True)
                    with open(filepath, 'w+') as target:
                        target.write(template_content)
                        logger.info(green("[>] " + filepath))
                
        else:
            logger.warning(f"nothing to do")
    
    def determine_severity(self, title) -> str:
        # Severity scores
        SEVERITY_LOW = 1
        SEVERITY_MEDIUM = 2
        SEVERITY_HIGH = 3
        SEVERITY_CRITICAL = 4

        score = 0

        if "Arbitrary File Upload" in title:
            score = SEVERITY_CRITICAL

        if "File Inclusion" in title:
            score = SEVERITY_CRITICAL
        
        if "SQL Injection" in title:
            score = SEVERITY_CRITICAL
        
        if "Unauthenticated PHP Object Injection" in title:
            score = SEVERITY_CRITICAL

        if "Remote Code Execution" in title:
            score = SEVERITY_CRITICAL
        
        if "Authentication Bypass" in title:
            score = SEVERITY_CRITICAL

        if "Cross-Site Scripting" in title:
            score = SEVERITY_HIGH
        
        if "Authorization Bypass" in title:
            score = SEVERITY_HIGH
        
        if "Missing Authorization" in title:
            score = SEVERITY_HIGH

        if "Username Enumeration" in title:
            score = SEVERITY_MEDIUM

        if "Cross-Site Request Forgery" in title:
            score = SEVERITY_MEDIUM

        if "Reflected Cross-Site Scripting" in title:
            score = SEVERITY_MEDIUM

        if "Authenticated" in title:
            """ Downsize the score if it's an "Authenticated" vulnerability """
            score = score - 1

        return "Critical" if score == 4 else "High" if score == 3 else "Medium" if score == 2 else "Low"

    def type_is_supported(self, software_type) -> bool:
        if software_type != "plugin" and software_type != "theme" and software_type != "core":
            return False
    
        return True
    
    def get_object_category_tag(self, software_type):
        return  "wp-theme" if software_type == "theme" else "wp-core" if software_type == "core" else "wp-plugin"

    def get_template_id(self, cve_id, vuln):
        if cve_id != "":
            logger.debug(f"[ ] CVE ID: {cve_id}")
            return cve_id
        
        unique_id = self.get_uniq_id(vuln.get('id', ''))

        object_slug = vuln.get('slug')

        logger.debug(f"[ ] No CVE ID. Created new unique ID: {unique_id}")
        return f"{object_slug}-{unique_id}"
    
    def target_version_file(self, software_type, vuln):
        object_slug = vuln.get('slug')
        if software_type == "theme":
            filepath = f"wp-content/themes/{object_slug}/style.css"
        elif software_type == "core":
            filepath = f"index.php"
        else:
            filepath = f"wp-content/plugins/{object_slug}/readme.txt"

        return filepath
    
    def get_version_regex(self, software_type):
        if software_type == "theme":
            regex = f"(?mi)Version: ([0-9.]+)"
        elif software_type == "core":
            regex = f"(?mi)\?v=([0-9.]+)"
        else:
            regex = f"(?mi)Stable tag: ([0-9.]+)"

        return regex

    def get_uniq_id(self, url: str):
        md5 = hashlib.md5(url.encode())
        return md5.hexdigest()
    
    def get_affected_version(self, affected_version) -> str:
        """ Turns the affected version string out of the API into nuclei readable format"""

        logger.debug(f"[ ] Affected version: {affected_version}")

        if affected_version['from_version'] == "*":
            return f"'<= {affected_version['to_version']}'"

        if affected_version['from_version'] == affected_version['to_version']:
            return f"'{affected_version['to_version']}'"

        return f"'>= {affected_version['from_version']}', '<= {affected_version['to_version']}'"

    def get_template_filename(self, software_type):
        if software_type == "core":
            return 'lib/template-wp-core.yaml'

        return 'lib/template.yaml'