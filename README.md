# nuclei-wordfence-cve

It's a kind of magic 🧙‍♀️

```shell
usage: main.py [-h] --url URL [--output OUTPUT] [--force] [--overwrite]

Process a Wordfence CVE report

options:
  -h, --help       show this help message and exit
  --url URL        the URL of the Wordfence CVE report. eg https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/houzez-login-register/houzez-login-register-263-privilege-
                   escalation
  --output OUTPUT  the output filename to store the nuclei-template in
  --force          ignore if there is already a template in the nuclei-templates repo
  --overwrite      ignore if there is already a template in our local nuclei-templates repo
```