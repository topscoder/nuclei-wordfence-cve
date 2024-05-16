from .colors import red, green, yellow
from .logger import logger
import hashlib
import json
import os
import requests
import re
from yaml import safe_load


class WordfenceAPIParser():

    url = None
    html_content = None
    edge_cases = None
    tpl_wp_core = None
    tpl_wp_core_no_ref = None
    tpl_main = None
    tpl_main_no_ref = None

    def run_local(self, local_file, overwrite=False, force=False, overwrite_enhanced=False) -> bool:
        return self.execute(local_file, True, overwrite, force, overwrite_enhanced)

    def run(self, url, overwrite=False, force=False, overwrite_enhanced=False) -> bool:
        return self.execute(url, False, overwrite, force, overwrite_enhanced)

    def execute(self, source, is_local=False, overwrite=False, force=False, overwrite_enhanced=False) -> bool:
        """Execute the Wordfence API Parser.

        Args:
            source (string): URL of the Wordfence API or path to local file.
            is_local (bool, optional): Whether or not the source file is a local file. Defaults to False.
            overwrite (bool, optional): Whether or not to overwrite the template if it already exists. Defaults to False.
            force (bool, optional): Whether or not to regenerate the template if it already exists. Defaults to False.

        Returns:
            bool: Template generated
        """

        parser_dir = os.path.dirname(os.path.realpath(__file__))
        yaml_file_path = os.path.join(parser_dir, "edge-cases.yaml")

        # Read the YAML file with edge cases and store in ram
        with open(yaml_file_path, "r") as yaml_file:
            self.edge_cases = safe_load(yaml_file)

        # Read the base templates and store in ram
        with open(self.get_template_filename('core')) as template:
            self.tpl_wp_core = template.read()

        with open(self.get_template_filename('core', False)) as template:
            self.tpl_wp_core_no_ref = template.read()

        with open(self.get_template_filename('main')) as template:
            self.tpl_main = template.read()

        with open(self.get_template_filename('main', False)) as template:
            self.tpl_main_no_ref = template.read()

        if is_local is True:
            if not source.lower().endswith(".json"):
                return False

            if not os.path.exists(source):
                return False

            with open(source, "r") as file:
                vulnerabilities = json.load(file)

                # Print the vulnerabilities
                for vulnerability_id, vulnerability in vulnerabilities.items():
                    self.process_item(vulnerability, overwrite, force, overwrite_enhanced)

        if is_local is False:
            if source is None or source.strip() == "":
                return False

            url = source.strip()

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
        id = json_object.get('id')
        description = json_object.get('description')
        if description is None:
            description = ""

        # CVE detection
        cve_id = json_object.get('cve')
        if cve_id is None:
            cve_id = ""

        software = json_object.get('software', [])
        if software:
            for item in software:
                software_type = item.get('type')
                software_slug = item.get('slug')

                # Try a fallback to find the CVE in the slug
                if cve_id == "":
                    # example: "slug": "UNKNOWN-CVE-2021-24916-1",
                    cve_pattern = r"CVE-\d{1,}-\d{1,}"
                    match = re.search(cve_pattern, item.get('slug'))

                    if match:
                        cve_number = match.group(0)
                        cve_id = cve_number
                    else:
                        cve_id = ""

                # determine slug for object category (plugins, themes)
                object_category_slug = "unknown"

                if software_type == 'plugin':
                    object_category_slug = "plugins"

                elif software_type == 'theme':
                    object_category_slug = "themes"

                elif software_type == 'core':
                    object_category_slug = "wordpress-core"

                # determine template filename
                template_id = self.get_template_id(cve_id, item, id)
                target_filename = template_id + ".yaml"
                logger.info(f"Target filename: {target_filename}")

                # determine file path
                year = ""
                if cve_id != "":
                    cve_parts = cve_id.split('-')
                    year = cve_parts[1]
                    filepath = f'nuclei-templates/{year}/{target_filename}'
                else:
                    filepath = f'nuclei-templates/cve-less/{object_category_slug}/{target_filename}'

                # Check to see if there is already a template for this vulnerability in our local templates repo
                if overwrite is False:
                    if os.path.isfile(f"{filepath}"):
                        logger.info(yellow(f"[*] Note: There is already a template for this vulnerability in our local nuclei-templates repo: {filepath}"))
                        logger.info(yellow("[*] Skipping. Use --overwrite if you want to ignore this and overwrite the template."))
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

                if self.type_is_supported(software_type) is False:
                    logger.warning(red(f"[*] Skipping. Software type {software_type} is not supported."))
                    # TODO could be a page with a vuln which affects more plugins/themes
                    # https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/fuse-social-floating-sidebar/appsero-121-missing-authorization
                    return False

                try:
                    cvss_score = json_object.get('cvss')['score']
                    cvss_rating = json_object.get('cvss')['rating']
                    cvss_vector = json_object.get('cvss')['vector']
                except Exception:
                    cvss_score = ""
                    cvss_rating = ""
                    cvss_vector = ""

                if cvss_rating == "" or "authenticated" in title.lower() or "authenticated" in description.lower():
                    cvss_rating = self.determine_severity(title, cvss_rating, description)

                reference_list = json_object.get('references', {})

                object_category_tag = self.get_object_category_tag(software_type)
                find_file = self.target_version_file(software_type, item)
                version_regex = self.get_version_regex(software_type, item)

                affected_versions = item.get('affected_versions')
                for version_range, version_data in affected_versions.items():
                    affected_version = self.get_affected_version(version_data)

                # Determine which base template we should use to parse content into
                # The template files are already read and stored into RAM
                if len(reference_list) > 0:
                    if software_type == "core":
                        template_content = self.tpl_wp_core
                    else:
                        template_content = self.tpl_main
                else:
                    if software_type == "core":
                        template_content = self.tpl_wp_core_no_ref
                    else:
                        template_content = self.tpl_main_no_ref

                # Prepare description to be YAML proof
                if description is not None:
                    lines = description.strip().splitlines()
                    description = '\n    '.join(lines)
                else:
                    description = ""

                # Parse contents into template and store to disk
                template_content = template_content.replace('__TEMPLATE_ID__', str(template_id))
                template_content = template_content.replace('__CVE_ID__', cve_id.strip())
                template_content = template_content.replace('__CVE_NAME__', title.strip())
                template_content = template_content.replace('__CVE_SEVERITY__', cvss_rating.strip().lower())
                template_content = template_content.replace('__CVE_DESCRIPTION__', description)
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

                with open(filepath, 'w') as target:
                    target.write(template_content)
                    logger.info(green("[>] " + filepath))
        else:
            logger.warning("nothing to do")

    def determine_severity(self, title, initial_rating, description) -> str:
        SEVERITY_LOW = 1
        SEVERITY_MEDIUM = 2
        SEVERITY_HIGH = 3
        SEVERITY_CRITICAL = 4

        score = 0
        if initial_rating == "Critical":
            score = SEVERITY_CRITICAL
        elif initial_rating == "High":
            score = SEVERITY_HIGH
        elif initial_rating == "Medium":
            score = SEVERITY_MEDIUM
        elif initial_rating == "Low":
            score = SEVERITY_LOW

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

        if "Authenticated" in title or "authenticated" in title:
            if "Unauthenticated" not in title and "unauthenticated" not in title:
                # Down-scale the score to Low if it's an "Authenticated" vulnerability
                score = SEVERITY_LOW

        if " Authenticated " in description or " authenticated " in description:
            # Down-scale the score to Low if it's an "Authenticated" vulnerability
            score = SEVERITY_LOW

        return "Critical" \
            if score == SEVERITY_CRITICAL \
            else "High" if score == SEVERITY_HIGH \
            else "Medium" if score == SEVERITY_MEDIUM \
            else "Low"

    def type_is_supported(self, software_type) -> bool:
        if software_type != "plugin" \
            and software_type != "theme" \
                and software_type != "core":
            return False

        return True

    def get_object_category_tag(self, software_type):
        return "wp-theme" \
            if software_type == "theme" \
            else "wp-core" if software_type == "core" \
            else "wp-plugin"

    def get_template_id(self, cve_id, software_item, id):
        """
        Creates a template id based on CVE or object slug and Wordfence ID
        Either:
            CVE-2024-1337-abcdef01234567hash
        Or:
            wordpress-abcdef01234567hash
        """

        # Use remediation to generate a unique id per software item
        # as there could be multiple software items for this specific plugin/theme
        # The remediation points out the version which is often unique per software item
        # and so is our unique id per software item
        remediation = software_item.get('remediation')
        unique_id = self.get_uniq_id(f"{id}-{remediation}")

        if cve_id != "":
            logger.debug(f"[ ] CVE ID: {cve_id}")
            return f"{cve_id}-{unique_id}"

        object_slug = software_item.get('slug').lower()

        logger.debug(f"[ ] No CVE ID. Using created ID: {unique_id}")
        return f"{object_slug}-{unique_id}"

    def target_version_file(self, software_type, vuln):
        object_slug = vuln.get('slug')

        if object_slug in self.edge_cases:
            obj = self.edge_cases.get(object_slug)
            filepath = obj.get('target')
        elif software_type == "theme":
            filepath = f"wp-content/themes/{object_slug}/style.css"
        elif software_type == "core":
            filepath = "index.php"
        else:
            filepath = f"wp-content/plugins/{object_slug}/readme.txt"

        return filepath

    def get_version_regex(self, software_type, vuln):
        object_slug = vuln.get('slug')

        if object_slug in self.edge_cases:
            obj = self.edge_cases.get(object_slug)
            regex = obj.get('regex')
        elif software_type == "theme":
            regex = "(?mi)Version: ([0-9.]+)"
        elif software_type == "core":
            regex = "(?mi)\?v=([0-9.]+)"
        else:
            regex = "(?mi)Stable tag: ([0-9.]+)"

        return regex

    def get_uniq_id(self, url: str):
        md5 = hashlib.md5(url.encode())
        return md5.hexdigest()

    def get_affected_version(self, affected_version) -> str:
        """
        Turns the affected version string out of the API
        into Nuclei readable format.
        """

        logger.debug(f"[ ] Affected version: {affected_version}")

        # Cast string to bool. In unit test it's a string, but in the API it's parsed to a boolean
        if affected_version['from_inclusive'] == "true":
            affected_version['from_inclusive'] = True

        if affected_version['from_inclusive'] == "false":
            affected_version['from_inclusive'] = False

        if affected_version['to_inclusive'] == "true":
            affected_version['to_inclusive'] = True

        if affected_version['to_inclusive'] == "false":
            affected_version['to_inclusive'] = False


        if affected_version['from_version'] == "*":
            if affected_version['to_inclusive'] == True:
                return f"'<= {affected_version['to_version']}'"
            else:
                return f"'< {affected_version['to_version']}'"

        if affected_version['from_version'] == affected_version['to_version']:
            return f"'{affected_version['to_version']}'"

        from_comparator = ">=" if affected_version['from_inclusive'] == True else ">"
        to_comparator = "<=" if affected_version['to_inclusive'] == True else "<"

        return f"'{from_comparator} {affected_version['from_version']}', '{to_comparator} {affected_version['to_version']}'"

    def get_template_filename(self, software_type, has_references=True):
        """
        Returns the right template for the specific case.
        Whether it has references or not and depending on software_type.
        """
        if has_references is False and software_type == "core":
            return 'src/base_templates/wp-core-without-references.yaml.template'

        if software_type == "core":
            return 'src/base_templates/wp-core.yaml.template'

        if has_references is False:
            return 'src/base_templates/main-without-references.yaml.template'

        return 'src/base_templates/main.yaml.template'
