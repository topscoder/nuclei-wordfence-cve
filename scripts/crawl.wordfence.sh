#!/bin/sh
#
# Required packages: katana, unfurl, anew
# Used sys: echo, tee, grep, sort, uniq, tee, wc
# Usage: sh ./scripts/crawl.wordfence.sh 
#
# Crawls wordfence.com and stores all urls in txt file
# - lib/sources/wordfence.com.crawler.txt
#
# It then greps all wordpress-core, wordpress-themes and wordpress-plugins urls and drops it in separate files
# - lib/sources/wordfence.com.wordpress-core.txt
# - lib/sources/wordfence.com.wordpress-themes.txt
# - lib/sources/wordfence.com.wordpress-plugins.txt
#
# And then it checks if there's a new URL for each of the three categories and drops to stdout
# - lib/sources/wordfence.com.wordpress-core.new.txt
# - lib/sources/wordfence.com.wordpress-themes.new.txt
# - lib/sources/wordfence.com.wordpress-plugins.new.txt
#

echo "=== CRAWLING ==="

katana -u https://wordfence.com/threat-intel/vulnerabilities/ -depth 10 | tee lib/sources/wordfence.com.crawler.txt

# Process plugins
cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/ | unfurl format %s://%d%p | sort | uniq | anew lib/sources/wordfence.com.wordpress-plugins.txt > lib/sources/wordfence.com.wordpress-plugins.new.txt
new_plugins=$(cat lib/sources/wordfence.com.wordpress-plugins.new.txt | wc -l | xargs)
echo "[>] NEW VULNERABILITIES FOR PLUGINS: ~ $new_plugins"
[[ $new_plugins -eq 0 ]]    || echo "Hint: python3 main.py --inputfile lib/sources/wordfence.com.wordpress-plugins.new.txt";

# Process themes
cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-themes/ | unfurl format %s://%d%p | sort | uniq | anew lib/sources/wordfence.com.wordpress-themes.txt > lib/sources/wordfence.com.wordpress-themes.new.txt
new_themes=$(cat lib/sources/wordfence.com.wordpress-themes.new.txt | wc -l | xargs)
echo "[>] NEW VULNERABILITIES FOR THEMES: ~ $new_themes"
[[ $new_themes -eq 0 ]]     || echo "Hint: python3 main.py --inputfile lib/sources/wordfence.com.wordpress-themes.new.txt";

# Process core
cat lib/sources/wordfence.com.crawler.txt | grep wordfence.com/threat-intel/vulnerabilities/wordpress-core/ | unfurl format %s://%d%p | sort | uniq | anew lib/sources/wordfence.com.wordpress-core.txt > lib/sources/wordfence.com.wordpress-core.new.txt
new_core=$(cat lib/sources/wordfence.com.wordpress-core.new.txt | wc -l | xargs)
echo "[>] NEW VULNERABILITIES FOR CORE: ~ $new_core"
[[ $new_core -eq 0 ]]       || echo "Hint: python3 main.py --inputfile lib/sources/wordfence.com.wordpress-core.new.txt";

