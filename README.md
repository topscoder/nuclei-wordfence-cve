<div align="center">
  <a href="https://github.com/topscoder/nuclei-wordfence-cve">
    <img width="100" align=center src="https://user-images.githubusercontent.com/86197446/225912783-bb6c5fa9-ce45-488b-a1fd-5af705b7cced.jpg">
  </a>
  <h1>Nuclei + Wordfence = ♥</h1>

  <h4><!-- START: __TOTAL_NUM_TEMPLATES -->46,760<!-- END: __TOTAL_NUM_TEMPLATES --> Nuclei Templates for WordPress Security Scanning 🥳</h4>
  
  <img src="https://img.shields.io/github/actions/workflow/status/topscoder/nuclei-wordfence-cve/test.yml?label=CI&logo=github&style=flat-square" height="20" alt="GitHub Workflow Status"> 
  <img src="https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white&style=flat-square" height="20" alt="pre-commit"> 
  <img src="https://img.shields.io/github/last-commit/topscoder/nuclei-wordfence-cve/main?style=flat-square&label=templates%20added" height="20" alt="Templates added"> 

</div>

---

Level up your WordPress security game! This project's got a treasure trove of fresh [Nuclei](https://github.com/projectdiscovery/nuclei) templates for WordPress. Scan for weaknesses in Core, plugins, and themes – all based on the latest intel from [Wordfence.com](https://www.wordfence.com/threat-intel/vulnerabilities/).

Here's why this is your new best friend:

* **Massive collection**: No more hunting for individual templates, you've got a whole arsenal at your fingertips.
* **Always on point**: These templates stay updated with the freshest threats, so you're never behind the curve.
* **Open source magic**: Need to tweak a template for a specific situation? No problem, you've got full control.

If you're guarding a WordPress site, this project is your secret weapon to identify vulnerabilities before the bad guys do.  Stop wasting time and secure your sites like a pro!

---

> [!TIP]
> If you found this project helpful, please consider giving it a star on GitHub.
> Your support helps to make this project even better. 🌟

### What's in it?!

<!-- START: __STATISTICS_TABLE -->
| category | total |
|---|---|
| wp-plugins | [43,775](https://github.com/search?q=%22wp-plugin%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| wp-themes | [2,235](https://github.com/search?q=%22wp-theme%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| wp-core | [743](https://github.com/search?q=%22wp-core%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| other | [16](https://github.com/search?q=repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML++NOT+%22wp-plugin%22+NOT+%22wp-core%22+NOT+%22wp-theme%22+path%3A%2F%5Enuclei-templates%5C%2F%2F&type=code&ref=advsearch) |


| severity | total |
|---|---|
| info | [7](https://github.com/search?q=%22severity%3A+info%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| low | [20,194](https://github.com/search?q=severity%3A+low+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| medium | [14,692](https://github.com/search?q=severity%3A+medium+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| high | [8,295](https://github.com/search?q=severity%3A+high+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
| critical | [3,571](https://github.com/search?q=severity%3A+critical+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch) |
<!-- END: __STATISTICS_TABLE -->

## Installation

To install this `nuclei-wordfence-cve` repository for use with Nuclei, you can use the following commands:

```bash
export GITHUB_TEMPLATE_REPO=topscoder/nuclei-wordfence-cve
nuclei -update-templates
```

### Usage

Once you have installed this template repo using the commands above, you can run the following command to scan for vulnerabilities using Nuclei:

```bash
nuclei -t github/topscoder/nuclei-wordfence-cve -u https://target.com
```

### Examples

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

## Protecting Customized Templates

To prevent accidental overwrites, you can mark templates you've manually customized with a comment at the end. Add the line `# Enhanced` as the last line of the template file.

## License

This project is licensed under the MIT License.

## Contact

If you have any questions or feedback, please feel free to contact the project maintainers.

~~ Please use it responsibly!
