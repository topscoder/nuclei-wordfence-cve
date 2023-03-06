#!/bin/sh
echo "CRAWLING" | lolcat

katana -u https://wordfence.com/threat-intel/vulnerabilities/ -depth 10 | tee lib/sources/wordfence.com.crawler.txt

cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-core/ | unfurl format %s://%d%p | sort | uniq | tee lib/sources/wordfence.com.wordpress-core.txt
cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-themes/ | unfurl format %s://%d%p | sort | uniq | tee lib/sources/wordfence.com.wordpress-themes.txt
cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/ | unfurl format %s://%d%p | sort | uniq | tee lib/sources/wordfence.com.wordpress-plugins.txt

# Show only new URLs
echo "\n\n NEW VULNERABILITIES FOR PLUGINS:\n" | lolcat
cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/ | unfurl format %s://%d%p | sort | uniq | anew lib/sources/wordfence.com.wordpress-plugins.txt
#cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/ | unfurl format %s://%d%p | sort | uniq | anew wordfence.com.wordpress-plugins.txt > lib/sources/wordfence.com.wordpress-plugins.new.txt

echo "\n\n NEW VULNERABILITIES FOR THEMES:\n" | lolcat
cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-themes/ | unfurl format %s://%d%p | sort | uniq | anew lib/sources/wordfence.com.wordpress-themes.txt
#cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-themes/ | unfurl format %s://%d%p | sort | uniq | anew wordfence.com.wordpress-themes.txt > lib/sources/wordfence.com.wordpress-themes.new.txt

echo "\n\n NEW VULNERABILITIES FOR CORE:\n" | lolcat
cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-core/ | unfurl format %s://%d%p | sort | uniq | anew lib/sources/wordfence.com.wordpress-core.txt
#cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-core/ | unfurl format %s://%d%p | sort | uniq | anew wordfence.com.wordpress-core.txt > lib/sources/wordfence.com.wordpress-core.new.txt