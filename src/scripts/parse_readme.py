import re
import glob


plugins = 0
themes = 0
core = 0
other = 0
critical = 0
high = 0
medium = 0
low = 0
info = 0
total = 0


for file in glob.glob("./nuclei-templates/**/*.yaml", recursive=True):
    total += 1
    with open(file) as f:
        content = f.read()

        if re.search("wp-plugin", content):
            plugins += 1

        if re.search("wp-theme", content):
            themes += 1

        if re.search("wp-core", content):
            core += 1

        if re.search("severity: info", content):
            info += 1

        if re.search("severity: low", content):
            low += 1

        if re.search("severity: medium", content):
            medium += 1

        if re.search("severity: high", content):
            high += 1

        if re.search("severity: critical", content):
            critical += 1


misc = len(glob.glob("./nuclei-templates/misc/*.yaml"))
apis = len(glob.glob("./nuclei-templates/apis/*.yaml"))
url_params = len(glob.glob("./nuclei-templates/url-params/*.yaml"))
wordpress_misc = len(glob.glob("./nuclei-templates/wordpress-misc/*.yaml"))

other = misc + apis + url_params + wordpress_misc

# Thousands separator formatting
plugins = '{:,}'.format(plugins)
themes = '{:,}'.format(themes)
core = '{:,}'.format(core)
other = '{:,}'.format(other)

info = '{:,}'.format(info)
low = '{:,}'.format(low)
medium = '{:,}'.format(medium)
high = '{:,}'.format(high)
critical = '{:,}'.format(critical)

total = '{:,}'.format(total)

table = "<!-- START: __STATISTICS_TABLE -->\n"
table += "<table width=\"100%\">\n"
table += "  <tr>\n"
table += "    <td width=\"50%\" valign=\"top\">\n"
table += "      <table>\n"
table += "        <thead>\n"
table += "          <tr><th align=\"left\">category</th><th align=\"left\">total</th></tr>\n"
table += "        </thead>\n"
table += "        <tbody>\n"
table += f"          <tr><td>wp-plugins</td><td><a href=\"https://github.com/search?q=%22wp-plugin%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch\">{plugins}</a></td></tr>\n"
table += f"          <tr><td>wp-themes</td><td><a href=\"https://github.com/search?q=%22wp-theme%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch\">{themes}</a></td></tr>\n"
table += f"          <tr><td>wp-core</td><td><a href=\"https://github.com/search?q=%22wp-core%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch\">{core}</a></td></tr>\n"
table += f"          <tr><td>other</td><td><a href=\"https://github.com/search?q=repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML++NOT+%22wp-plugin%22+NOT+%22wp-core%22+NOT+%22wp-theme%22+path%3A%2F%5Enuclei-templates%5C%2F%2F&type=code&ref=advsearch\">{other}</a></td></tr>\n"
table += "        </tbody>\n"
table += "      </table>\n"
table += "    </td>\n"
table += "    <td width=\"50%\" valign=\"top\">\n"
table += "      <table>\n"
table += "        <thead>\n"
table += "          <tr><th align=\"left\">severity</th><th align=\"left\">total</th></tr>\n"
table += "        </thead>\n"
table += "        <tbody>\n"
table += f"          <tr><td>critical</td><td><a href=\"https://github.com/search?q=severity%3A+critical+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch\">{critical}</a></td></tr>\n"
table += f"          <tr><td>high</td><td><a href=\"https://github.com/search?q=severity%3A+high+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch\">{high}</a></td></tr>\n"
table += f"          <tr><td>medium</td><td><a href=\"https://github.com/search?q=severity%3A+medium+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch\">{medium}</a></td></tr>\n"
table += f"          <tr><td>low</td><td><a href=\"https://github.com/search?q=severity%3A+low+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch\">{low}</a></td></tr>\n"
table += f"          <tr><td>info</td><td><a href=\"https://github.com/search?q=%22severity%3A+info%22+repo%3Atopscoder%2Fnuclei-wordfence-cve+language%3AYAML&type=code&ref=advsearch\">{info}</a></td></tr>\n"
table += "        </tbody>\n"
table += "      </table>\n"
table += "    </td>\n"
table += "  </tr>\n"
table += "</table>\n"
table += "<!-- END: __STATISTICS_TABLE -->"


def write_string_to_file(string, target_file, marker_start, marker_end):
    marker = f"{marker_start}.*{marker_end}"
    with open(target_file, "r") as f:
        content = f.read()
        content = re.sub(marker, string, content, 0, re.S)

        with open(target_file, "w") as f2:
            f2.write(content)

total_marker = f"<!-- START: __TOTAL_NUM_TEMPLATES -->{total}<!-- END: __TOTAL_NUM_TEMPLATES -->"

write_string_to_file(total_marker, "README.md", "<!-- START: __TOTAL_NUM_TEMPLATES -->", "<!-- END: __TOTAL_NUM_TEMPLATES -->")
write_string_to_file(table, "README.md", "<!-- START: __STATISTICS_TABLE -->", "<!-- END: __STATISTICS_TABLE -->")
