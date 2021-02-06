
### About

- The focus here is on generating a list which doesn't hamper usability while not compromising on privacy/security.  
  
- The sources for the list is carefully curated to include lists which are regularly maintained and have minimum overlaps.  
  
- Whitelists are extensively employed to make sure false positives do not occur.  
  
- By making use of regex and ABP style the size of the list is kept to a minimum.  
  - If a domain is already blocked, its subdomains are removed from the list.  
  - By employing regex rules, only those rules which are not matched are kept on.  
  - The whitelist is compared with the regex rules to ensure no safe-domain is ensured that no useful domain is inadvertently blocked.  
  
### Usage  

- [AdGuardHome](https://github.com/AdguardTeam/AdGuardHome/)  
- [Blocky](https://github.com/0xERR0R/blocky/)  
  
NOTE: It will work wherever ABP format is supported, ex: ublock origin, but is best used for filtering DNS queries.  
  
### Support  

- Report false-positives or bad domains  
- Improve generator script by making a PR
- Support via
  - [PayPal](http://paypal.me/arapurayil)  
  - [Ko-fi](https://ko-fi.com/arapurayil)  
  - [Liberapay](https://liberapay.com/arapurayil)  
  - [Patreon](https://www.patreon.com/arapurayil)
