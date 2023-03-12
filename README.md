# nuclei-wordfence-cve 

It's a kind of magic 🧙‍♀️ 

### Overview 

<!-- START: __STATISTICS_TABLE -->
| templates | total |
|---|---|
| wp-plugins | 5189 |
| wp-themes | 130 |
| wp-core | 0 |
| other | 1 |
<!-- END: __STATISTICS_TABLE --> 

### Usage 

```shell 
usage: main.py [-h] [--inputfile INPUTFILE] [--url URL] [--outputfile OUTPUTFILE] [--force] [--overwrite] [--threads THREADS] 

Generate a Nuclei template out of a Wordfence CVE report 🧙‍♀️ 

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
