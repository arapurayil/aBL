
# Adur Block List (ABL)

## The General List

This is the default list which blocks ads, tracking, telemetry,
phishing, malware, cryptojacking and other such undesirables

### Sources

| #    | Title                                                                                                                  | Blocked | Unblocked |
| :--- | :--------------------------------------------------------------------------------------------------------------------- | :------ | :---- |
| 01   | [AdGuard Base filter](https://filters.adtidy.org/extension/chromium/filters/2.txt)                                     | 2968    | 29    |
| 02   | [AdGuard Mobile Ads filter](https://filters.adtidy.org/extension/chromium/filters/11.txt)                              | 947     | 2     |
| 03   | [AdGuard Tracking Protection filter](https://filters.adtidy.org/extension/chromium/filters/3.txt)                      | 1653    | 9     |
| 04   | [anudeepND blacklist](https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt)                      | 38336   | 0     |
| 05   | [anudeepND whitelist](https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt)              | 0       | 194   |
| 06   | [CHEF-KOCH NSABlocklist](https://github.com/CHEF-KOCH/NSABlocklist/raw/master/HOSTS/HOSTS)                             | 8191    | 0     |
| 07   | [EasyList](https://easylist.to/easylist/easylist.txt)                                                                  | 1861    | 2     |
| 08   | [EasyPrivacy](https://easylist.to/easylist/easyprivacy.txt)                                                            | 2709    | 0     |
| 09   | [NextDNS cname-cloaking-blocklist (forked)](https://github.com/arapurayil/cname-cloaking-blocklist/raw/master/domains) | 18      | 0     |
| 10   | [Personal Blocklist by WaLLy3K](https://v.firebog.net/hosts/static/w3kbl.txt)                                          | 739     | 0     |
| 11   | [project-level blocklist](https://github.com/arapurayil/ABL/raw/master/sources/_block.txt)                             | 0       | 0     |
| 12   | [project-level unblocklist](https://github.com/arapurayil/ABL/raw/master/sources/_unblock.txt)                         | 0       | 0     |
| 13   | [StevenBlack hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)                                  | 54282   | 0     |

#### Statistics

| Blocked domains                          | #        |
| :--------------------------------------- | :------- |
| unprocessed                              | 111704   |
| minus duplicates and false positives     | 93857    |

## The Anti-Porn Addon List

Blocks porn

### Sources

| #    | Title                                                                                                                                            | Blocked | Unblocked |
| :--- | :----------------------------------------------------------------------------------------------------------------------------------------------- | :------ | :--- |
| 01   | [Chad Mayfield's Porn List Light](https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list) | 11868   | 0    |
| 02   | [Clefspeare13's pornhosts](https://raw.githubusercontent.com/Clefspeare13/pornhosts/master/0.0.0.0/hosts)                                        | 8930    | 0    |
| 03   | [Sinfonietta's Pornography Hosts](https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts)                              | 14208   | 0    |

#### Statistics

| Blocked domains                          | #       |
| :--------------------------------------- | :------ |
| unprocessed                              | 35006   |
| minus duplicates and false positives     | 18971   |
