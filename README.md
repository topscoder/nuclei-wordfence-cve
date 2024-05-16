<div align="center">
  <a href="https://github.com/topscoder/nuclei-wordfence-cve">
    <img width="100" align=center src="https://user-images.githubusercontent.com/86197446/225912783-bb6c5fa9-ce45-488b-a1fd-5af705b7cced.jpg">
  </a>
  <h1>Nuclei + Wordfence = ♥</h1>
  <a href="https://github.com/topscoder/nuclei-wordfence-cve/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/topscoder/nuclei-wordfence-cve/test.yml?label=CI&logo=github&style=flat-square" height="20" alt="GitHub Workflow Status">
  </a>
  <a href="https://github.com/pre-commit/pre-commit">
    <img src="https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white&style=flat-square" height="20" alt="pre-commit">
  </a>
<!-- Short description: -->
  <h3>WordPress related Nuclei templates: <!-- START: __TOTAL_NUM_TEMPLATES -->36,359<!-- END: __TOTAL_NUM_TEMPLATES --> 🥳</h3>
</div>

This project provides a massive up-to-date collection of WordPress related Nuclei templates that can be used to scan for vulnerabilities in WordPress Core, WordPress Plugins and WordPress Themes. The templates are based on the vulnerability reports of [Wordfence.com](https://www.wordfence.com/threat-intel/vulnerabilities/).

This project is a valuable resource for anyone who wants to scan for vulnerabilities in WordPress-based websites. The templates are easy to use and up-to-date, and they are open source so you can modify them to fit your specific needs. If you are responsible for the security of a website that uses WordPress, I highly recommend using this project to scan for vulnerabilities.

> [!TIP]
> If you found this project helpful, please consider giving it a star on GitHub.
> Your support helps to make this project even better. 🌟

## Features

* The templates are easy to use and can be run with a single command.
* The templates are based on the vulnerability reports of Wordfence.com.
* The templates are updated regularly to ensure that they are always up-to-date with the latest vulnerabilities.
* The templates are open source, so you can modify them to fit your specific needs.
* Manually enhanced templates can be marked to avoid overwriting them.

### What's in it?!

<!-- START: __STATISTICS_TABLE -->
| category | total |
|---|---|
| wp-plugins | [33,802](https://github.com/search?q=%22wp-plugin%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| wp-themes | [1,817](https://github.com/search?q=%22wp-theme%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| wp-core | [733](https://github.com/search?q=%22wp-core%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| other | [16](https://github.com/search?q=repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML++NOT+%22wp-plugin%22+NOT+%22wp-core%22+NOT+%22wp-theme%22+path%3A%2F%5Enuclei-templates%5C%2F%2F&type=code&ref=advsearch) |


| severity | total |
|---|---|
| info | [7](https://github.com/search?q=%22severity%3A+info%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| low | [13,978](https://github.com/search?q=severity%3A+low+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| medium | [12,196](https://github.com/search?q=severity%3A+medium+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| high | [7,336](https://github.com/search?q=severity%3A+high+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| critical | [2,841](https://github.com/search?q=severity%3A+critical+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
<!-- END: __STATISTICS_TABLE -->

## Usage

To use the templates, you will need to install [Nuclei](https://github.com/projectdiscovery/nuclei) and this `nuclei-wordfence-cve` repository. Once you have installed Nuclei, you can run the following command to scan for vulnerabilities:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -u https://target.com
```

## Installation

To install this `nuclei-wordfence-cve` repository, you can use the following command:

```bash
export GITHUB_TEMPLATE_REPO=topscoder/nuclei-wordfence-cve
nuclei -update-templates
```

## Examples

Here are some examples how to use the templates:

* To scan for **all known vulnerabilities** in WordPress, you can run the following command:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -u https://target.com
```

* To scan for a **CVE specific vulnerability**, you can run the following command:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -template-id cve-2023-32961 -u https://target.com
```

* To scan only for **critical vulnerabilities**, you can run the following command:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -severity critical -u https://target.com
```

* To scan only for **WordPress core vulnerabilities**, you can run the following command:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -tags wp-core -u https://target.com
```

* To scan only for **WordPress plugin vulnerabilities**, you can run the following command:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -tags wp-plugin -u https://target.com
```

* To scan only for **WordPress theme vulnerabilities**, you can run the following command:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -tags wp-theme -u https://target.com
```

* To go wild, you can combine and combine and combine:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -tags wp-plugin,wp-theme -severity critical,high
```

* To go even wilder, you can use the template condition flag (`-tc`) that allows complex expressions like the following ones:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -template-condition "contains(to_lower(name),'cross-site scripting') || contains(to_upper(name),'XSS')" -u https://target.com
nuclei -t github/topscoder/nuclei-wordfence-cve -template-condition "contains(to_lower(name),'sql injection') || contains(to_lower(description),'sql injection')" -u https://target.com
nuclei -t github/topscoder/nuclei-wordfence-cve -template-condition "contains(to_lower(name),'file inclusion') || contains(to_lower(description),'file inclusion')" -u https://target.com
nuclei -t github/topscoder/nuclei-wordfence-cve -template-condition "contains(to_upper(name),'CSRF') || contains(to_upper(description),'CSRF')" -u https://target.com
```

## Contributing

If you would like to contribute to this project, please feel free to fork the repository and submit a pull request.

## Manually Enhanced

Manually enhanced templates can be marked with `# Enhanced` in last line of the template to avoid the template to be overwritten by accident.

## License

This project is licensed under the MIT License.

## Contact

If you have any questions or feedback, please feel free to contact the project maintainers.

~~ Please use it responsibly!
