# nuclei-wordfence-cve

It's a kind of magic 🧙‍♀️

```shell
usage: main.py [-h] [--inputfile INPUTFILE] [--url URL] [--outputfile OUTPUTFILE] [--force] [--overwrite] [--threads THREADS]

Process a Wordfence CVE report

options:
  -h, --help            show this help message and exit
  --inputfile INPUTFILE
                        file containing Urls to Wordfence CVE reports
  --url URL             the URL of the Wordfence CVE report. eg https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/houzez-login-register/houzez-login-register-263-privilege-escalation
  --outputfile OUTPUTFILE
                        the output filename to store the nuclei-template in
  --force               ignore if there is already a template in the official nuclei-templates repo
  --overwrite           ignore if there is already a template in our local nuclei-templates repo
  --threads THREADS     boost by increasing the default worker threads (default 2)
```

```shell
katana -u https://www.wordfence.com -depth 10 -timeout 2 | grep wordfence.com/threat-intel/vulnerabilities/wordpress- | grep -v wordpress-core | unfurl format %s://%d%p | sort | uniq | tee urls.uniq2.txt
```