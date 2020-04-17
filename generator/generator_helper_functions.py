import json
from concurrent.futures.thread import ThreadPoolExecutor

from progiter import ProgIter
from tldextract import tldextract

import dns.resolver
import regex as re
from pathlib import Path
from validators import domain
from pip._vendor import requests


def is_path(path):
    """
    Creates file or dir if path doesn't exist

    :param path: path
    :return: path
    """

    if Path(path).suffix:
        if not Path(path).exists():
            Path(path).open("x", encoding="utf-8").close()
        return Path(path)
    if not Path(path).exists():
        Path(path).mkdir()

    return Path(path)


def read_file(path, data_type="list"):
    """
    Reads a file and returns its contents

    :param path: the input file
    :param data_type: the return data type
    :return: the contents of the file
    """
    if Path(path).suffix == ".json":
        with open(path, "r", encoding="utf-8") as file:
            data_json = json.load(file)
            return data_json
    else:
        with open(path, "r", encoding="utf-8") as file:
            if data_type == "list":
                content = file.readlines()
            else:
                content = file.read()
            return content


def write_file(data, path):
    """
    Writes a file with given data

    :param data: content to be written
    :param path: the output file
    """
    if Path(path).suffix == ".json":
        if isinstance(data, str):
            data = json.loads(data)
        with open(path, "w", encoding="utf-8") as file:
            file.seek(0)
            json.dump(data, file, indent=4)
            file.truncate()
    else:
        with open(path, "w", encoding="utf-8") as output_file:
            for line in data:
                output_file.write(line)


def get_response(url):
    """
    Gets response headers

    :param url: the url to get the headers for
    :return: the response
    """
    session = requests.Session()
    header = {"User-Agent": "Arapurayil"}
    response = session.get(url, allow_redirects=True, timeout=30, headers=header)
    return response


def get_content(url):
    """
    Gets the content from the url

    :param url: the url to get the content for
    :return: content
    """
    content = get_response(url).content.decode("utf-8")
    return content


def get_last_modified(url):
    """
    Gets the last-modified tag if present,
    if not will get the etag

    :param url: the url to get the headers for
    :return: either the last-modified tag, etag or false
    """
    if "last-modified" not in get_response(url).headers:
        if "etag" in get_response(url).headers:
            return get_response(url).headers["etag"]
        return False
    return get_response(url).headers["last-modified"]


def extract_abp(content):
    """
    Extracts blocked and unblocked domains from ABP style content

    :param content: the input content
    :return: blocked and unblocked domains
    """
    pattern_list = [
        r"^#.*|^!.*",
        r".*##.*",
        r".*#@#.*",
        r".*#\$#.*",
        r".*#@\$#.*",
        r".*#\?#.*",
        r".*#\$\?#.*",
        r".*\$\$.*",
        r".*\$@\$.*",
        r".*#%#.*",
        r".*#@%#.*",
        r".*/.*",
    ]
    pattern = re.compile("|".join(f"(?:{p})" for p in pattern_list))

    pattern_blocked_list = [
        r"^(\|\|)(www\.|m\.)",
        r"^(\|\|)",
        r"\^$",
        r"\^.*(\bthird-party\b|\b3p\b|\bdocument\b|\ball\b|\bpopup\b).*",
    ]
    pattern_blocked = re.compile("|".join(f"(?:{p})" for p in pattern_blocked_list))

    pattern_unblocked_list = [r"^(@@\|\|)", r"\^$"]
    pattern_unblocked = re.compile(
        "|".join(f"(?:{p})" for p in pattern_unblocked_list)
    )

    content = [re.sub(pattern, '', item) for item in content]

    content_blocked = [item for item in content if re.match(r"^(\|\|).*\^", item, concurrent=True)]
    content_blocked = [re.sub(pattern_blocked, '', item, concurrent=True) for item in content_blocked]

    content_unblocked = [item for item in content if re.match(r"^(@@\|\|).*\^$", item, concurrent=True)]
    content_unblocked = [re.sub(pattern_unblocked, '', item, concurrent=True) for item in content_unblocked]

    blocked = [item for item in content_blocked if domain(item)]
    unblocked = [item for item in content_unblocked if domain(item)]

    return blocked, unblocked


def extract_hosts(content, is_not):
    """
    Extracts blocked or unblocked domains from hosts/domains style content

    :param content: the input content
    :param is_not: to identify if the content is a block-list or an unblock-list
    :return: blocked and unblocked domains
    """
    pattern_list = [
        r"^#.*|^!.*",
        r"^\d*\.\d*\.\d*\.\d*\s*(\s|www\.|m\.)",
        r"^(www\.|m\.)",
        r".*::1.*",
        r"\s.*\#.*",
    ]
    pattern = re.compile("|".join(f"(?:{p})" for p in pattern_list))

    content = [re.sub(pattern, '', item, concurrent=True) for item in content]

    domains = [item for item in content if domain(item)]

    blocked, unblocked = [], []
    if is_not:
        unblocked = domains
    else:
        blocked = domains

    return blocked, unblocked


def get_cname(domains):
    """
    Gets cname of a list of domains
    :param domains: the input list of domains
    :return:domains with cname, domains without cname
    """
    domains_cname, domains_no_cname = [], []

    dns_resolver = dns.resolver.Resolver()
    dns_resolver.nameservers = [
        "8.8.8.8",
        "2001:4860:4860::8888",
        "8.8.4.4",
        "2001:4860:4860::8844",
    ]
    dns_resolver.lifetime = dns_resolver.timeout = 5

    def worker(item):
        try:
            answer = dns_resolver.query(item, "CNAME")
            for cname_val in answer:
                domains_cname.append(str(cname_val.target).rstrip("."))
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            domains_no_cname.append(item)
        except dns.exception.Timeout:

            pass

    pool = ThreadPoolExecutor(max_workers=1000)
    with pool:
        pool.map(worker, domains)

    return domains_cname, domains_no_cname


def extract_tld(domain):
    extract = tldextract.TLDExtract(include_psl_private_domains=True)
    return extract(domain)


def match_pattern(content, pattern, desc):
    """
    Matches content with the regex pattern

    :param content: the input content
    :param pattern: the regex pattern
    :param desc: the description in the progress bar
    :return: matched and unmatched contents
    """
    matched = [item for item in ProgIter(content, desc=f'{desc}') if re.match(pattern,item, concurrent=True)]
    unmatched = list(set(content) - set(matched))

    return matched, unmatched
