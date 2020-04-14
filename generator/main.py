"""
The Adur Block List Generator.
"""
import base64
import glob
import hashlib
import json
import textwrap
from collections import Counter
from concurrent.futures.thread import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from itertools import chain, groupby
from pathlib import Path

import regex as re
import dns.resolver
import requests
from progiter import ProgIter
from tldextract import tldextract
from validators import domain as valid_domain


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


def dir_empty(path):
    """
    Checks if directory is empty

    :param path: path
    :return: true/false
    """
    if not any(Path(path).iterdir()):
        return True
    return False


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


def get_last_modified(url):
    """
    Gets the last-modified tag if present,
    if not will get the etag

    :param url: the url to get the headers for
    :return: either the last-modified tag, etag or false
    """
    session = requests.Session()
    header = {"User-Agent": "Arapurayil"}
    response = session.head(url, allow_redirects=True, timeout=5, headers=header)
    if "last-modified" not in response.headers:
        if "etag" in response.headers:
            return response.headers["etag"]
        return False
    return response.headers["last-modified"]


def get_content(url):
    """
    Gets the content from the url

    :param url: the url to get the content for
    :return: content
    """
    session = requests.Session()
    header = {"User-Agent": "Arapurayil"}
    response = session.get(url, allow_redirects=True, timeout=30, headers=header)
    content = response.content.decode("utf-8")
    return content


def get_default(path, file_name, url):
    """
    Get the default content for a file

    :param path: the output file
    :param file_name: the name of the output file
    :param url: the url to fetch the content from
    """
    write_file(get_content(url), Path.joinpath(path, file_name))
    print(f"""Fetched {file_name} for {path} from {url}""")


def extract_abp(content):
    """
    Extracts blocked and unblocked domains from ABP style content

    :param content: the input content
    :return: blocked and unblocked domains
    """
    blocked_domains, unblocked_domains = [], []
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
    pattern = re.compile("|".join("(?:%s)" % p for p in pattern_list))

    pattern_unblocked_list = [r"^@@\|\|", r"\^$"]
    pattern_unblocked = re.compile(
        "|".join("(?:%s)" % p for p in pattern_unblocked_list)
    )

    pattern_blocked_list = [
        r"^(\|\|)(www\.|m\.)",
        r"^\|\|",
        r"\^$",
    ]
    pattern_blocked = re.compile("|".join("(?:%s)" % p for p in pattern_blocked_list))

    for line in content:
        line = re.sub(pattern, r"", line, concurrent=True)
        if re.match(r"^@@\|\|.*\^$", line, concurrent=True):
            line = re.sub(pattern_unblocked, r"", line, concurrent=True)
            if line != "":
                unblocked_domains.append(line.lstrip())
        if re.match(r"^\|\|.*\^$", line, concurrent=True):
            line = re.sub(pattern_blocked, r"", line, concurrent=True)
            if line != "":
                blocked_domains.append(line.lstrip())

    return sorted(blocked_domains), sorted(unblocked_domains)


def extract_hosts(content, is_not):
    """
    Extracts blocked or unblocked domains from hosts/domains style content

    :param content: the input content
    :param is_not: to identify if the content is a block-list or an unblock-list
    :return: blocked and unblocked domains
    """
    domains, blocked, unblocked = [], [], []
    pattern_list = [
        r"^#.*|!.*",
        r"^\d*\.\d*\.\d*\.\d*\s*(\s|www\.|m\.)",
        r"^(www\.|m\.)",
        r".*::1.*",
    ]
    pattern = re.compile("|".join("(?:%s)" % p for p in pattern_list))

    for line in content:
        line = re.sub(pattern, r"", line, concurrent=True)
        if line != "":
            domains.append(line.lstrip())

    if is_not:
        unblocked = domains
    else:
        blocked = domains

    return sorted(blocked), sorted(unblocked)


def de_duplicate(content):
    """
    Removes duplicates

    :param content: the input
    :return: list of unique items
    """
    content = sorted(content)
    return [k for k, v in groupby(content)]


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


def separate_wildcard(content):
    """
    Separates lines with * in them
    :param content: the input content
    :return: list of lines without *, list of lines with *
    """
    wildcard = [x for x in content if "*" in x]
    non_wildcard = [x for x in content if x not in wildcard]

    return non_wildcard, wildcard


def match_pattern(content, pattern, desc):
    """
    Matches content with the regex pattern

    :param content: the input content
    :param pattern: the regex pattern
    :param desc: the description in the progress bar
    :return: matched and unmatched contents
    """
    matched, unmatched = [], []

    def worker(item):
        if re.match(pattern, item, concurrent=True):

            matched.append(item)
        else:
            unmatched.append(item)

    pool = ThreadPoolExecutor()
    with pool:
        list(
            ProgIter(
                pool.map(worker, content),
                total=len(content),
                desc=f"{desc}",
                leave=False,
            )
        )

    return matched, unmatched


def gen_lists(blg, blocked):
    """
    Generates blocklist files in ABP format and domains format

    :param blg: the main class
    :param blocked: the blocked domains
    :return: the path of the blocklist file in ABP format
    """
    last_modified = datetime.now().strftime("%d %b %Y %H:%M:%S IST")
    abp_pre_header = "[Adblock Plus 2.0]\n"
    list_title = f"{blg.header.title} - {blg.list_title}"

    header = (
        f"sym_cmt Title: {list_title}\n"
        f"sym_cmt Author: {blg.header.author}\n"
        f"sym_cmt Description: {blg.data_json[blg.j_key.description]}\n"
        f"sym_cmt Version: {blg.header.version}\n"
        f"sym_cmt Last modified: {last_modified}\n"
        f"sym_cmt Expires: {blg.header.expires} (update frequency)\n"
        f"sym_cmt\n"
        f"sym_cmt Repository: {blg.header.repo}\n"
        f"sym_cmt You can find lists for other categories in the repo\n"
        f"sym_cmt There is also a alt_list version\n"
        f"sym_cmt\n"
        f"sym_cmt Issues: {blg.header.issues}\n"
        f"sym_cmt Please report false positives or unblocked domains through Issues\n"
        f"sym_cmt\n"
        f"sym_cmt Licence: {blg.header.license}\n"
        f"sym_cmt-----------------------------------------"
        f"---------------------------------------------sym_cmt\n"
    )

    file_domains = is_path(Path.joinpath(blg.dir, blg.f_out.domains))
    file_blocklist = is_path(Path.joinpath(blg.dir, blg.f_out.blocklist))
    blocked_domains = [x + "\n" for x in sorted(blocked)]

    with open(file_domains, "w", encoding="utf-8") as file:
        file.write(header.replace("sym_cmt", "#").replace("alt_list", "ABP"))
        for line in blocked_domains:
            file.write(line)

    blocklist = [x.replace(x, f"||{x}^\n") for x in sorted(blocked)]
    with open(file_blocklist, "w", encoding="utf-8") as file:
        file.write(abp_pre_header)
        file.write(header.replace("sym_cmt", "!").replace("alt_list", "domains"))
        for line in blocklist:
            file.write(line)

    return file_blocklist


def write_stats(blg, stats):
    """
    Writes statistics to the stats json file

    :param blg: the main class
    :param stats: the input stats content
    """
    file_stats = is_path(Path.joinpath(blg.dir, blg.f_out.stats))
    write_file(stats, file_stats)


def gen_checksum(file_blocklist):
    """
    Generates and add the checksum to the input file
    adapted from https://github.com/adblockplus/adblockplus/blob/master/addChecksum.py

    :param file_blocklist:  the blocklist file in ABP format
    """
    checksum_pattern = re.compile(
        r"^\s*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n", re.I | re.M
    )

    def add_checksum(in_data):
        checksum = calculate_checksum(in_data)
        re.sub(checksum_pattern, "", in_data)
        out_data = re.sub(r"(\r?\n)", r"\1! Checksum: %s\1" % checksum, in_data, 1)
        return out_data

    def calculate_checksum(in_data):
        md5 = hashlib.md5()
        md5.update(normalize(in_data).encode("utf8"))
        encoded_cs = base64.b64encode(md5.digest()).decode("utf8").rstrip("=")
        return encoded_cs

    def normalize(in_data):
        re.sub(r"\r", "", in_data)
        re.sub(r"\n+", "\n", in_data)
        out_data = re.sub(checksum_pattern, "", in_data)
        return out_data

    with open(file_blocklist, "r", encoding="utf8") as file:
        read_data = file.read()

    data = add_checksum(read_data)
    write_file(data, file_blocklist)


def gen_md_category(blg, stats):
    """
    Generate README.md for the category

    :param blg: the main class
    :param stats: statistics
    :return: the markdown content
    """
    blg.data_json[blg.j_key.sources] = sorted(
        blg.data_json[blg.j_key.sources], key=lambda x: x[blg.i_key.title].upper()
    )

    def data_md():
        def section_one():
            heading_h1 = f"""# The {blg.list_title}"""
            desc = f"""{textwrap.fill(blg.data_json[blg.j_key.description])}"""
            content_section_one = chain("\n", heading_h1, "\n\n", desc, "\n")
            return content_section_one

        def section_two():
            heading_h2 = "## Sources"
            tbl = []

            tbl_c1 = "#"
            len_c1 = len(":---")
            tbl_c2 = "Title"
            len_c2 = len(":---")
            tbl_c3 = "Blocked"
            len_c3 = len(":---")
            tbl_c4 = "Unblocked"
            len_c4 = len(":---")

            for index, key in enumerate(blg.data_json[blg.j_key.sources]):
                if len(str({index + 1}).zfill(2)) > len_c1:
                    len_c1 = len(str({index + 1}).zfill(2))
                if len(str(f"[{key[blg.i_key.title]}]({key[blg.i_key.url]})")) > len_c2:
                    len_c2 = len(str(f"[{key[blg.i_key.title]}]({key[blg.i_key.url]})"))
                if len(str({key[blg.i_key.num_blocked]})) > len_c3:
                    len_c3 = len(str({key[blg.i_key.num_blocked]}))
                if len(str({key[blg.i_key.num_unblocked]})) > len_c4:
                    len_c4 = len(str({key[blg.i_key.num_unblocked]}))

            tbl_title = (
                f"| {tbl_c1.ljust(len_c1)} | {tbl_c2.ljust(len_c2)} | {tbl_c3.ljust(len_c3)} | {tbl_c4.ljust(len_c4)} |\n"
                f"| {':---'.ljust(len_c1, '-')} | {':---'.ljust(len_c2, '-')} | {':---'.ljust(len_c3, '-')} | {':---'.ljust(len_c4, '-')} |\n"
            )

            tbl.append(tbl_title)

            for index, key in enumerate(blg.data_json[blg.j_key.sources]):
                tbl_contents = (
                    f"| {str(index + 1).zfill(2).ljust(len_c1)} | {str(f'[{key[blg.i_key.title]}]({key[blg.i_key.url]})').ljust(len_c2)} "
                    f"| {str(key[blg.i_key.num_blocked]).ljust(len_c3)} | {str(key[blg.i_key.num_unblocked]).ljust(len_c4)} |\n"
                )

                tbl.append(tbl_contents)

            content_section_two = chain("\n", heading_h2, "\n\n", tbl)
            return content_section_two

        def section_three():
            heading_h2 = "### Statistics"
            tbl = []
            tbl_c1 = "Blocked domains"
            len_c1 = len(":---")
            tbl_c2 = "#"
            len_c2 = len(":---")

            for key in stats:
                if len(str({key})) > len_c1:
                    len_c1 = len(str({key}))
                if len(str({stats[key]})) > len_c2:
                    len_c2 = len(str({stats[key]}))

            tbl_title = (
                f"| {tbl_c1.ljust(len_c1)} | {tbl_c2.ljust(len_c2)} |\n"
                f"| {':---'.ljust(len_c1, '-')} | {':---'.ljust(len_c2, '-')} |\n"
            )
            tbl.append(tbl_title)

            for key in stats:
                tbl_contents = (
                    f"| {str(key).ljust(len_c1)} | {str(stats[key]).ljust(len_c2)} |\n"
                )
                tbl.append(tbl_contents)

            content_section_three = chain("\n", heading_h2, "\n\n", tbl)
            return content_section_three

        md_content = chain(section_one(), section_two(), section_three())
        return md_content

    file_md_category = is_path(Path.joinpath(blg.dir, "README.md"))
    write_file(data_md(), file_md_category)


def concat_md_category(blg, out_file):
    """
    Concatenate all the category README.md files

    :param blg: the main class
    :param out_file: README.md file for ABL
    """
    for file in glob.glob(f"{blg.lists}/*/*.md"):
        with open(file, "r") as file_input, open(out_file, "a") as file_output:
            for line in file_input:
                if re.match(r"^(#|##|###)\s", line):
                    line = re.sub(r"^#", r"##", line)
                file_output.write(line)


def gen_md_blocklist(blg):
    """
    Generate README.md for ABL from category README.md files

    :param blg: the main class
    """
    file_about = is_path(Path.joinpath(BASE, "ABOUT.md"))
    about = read_file(file_about, data_type="str")
    if about:
        intro = about
    else:
        intro = f"\n# {blg.header.title}\n"

    file_md_blocklist = Path.joinpath(BASE, "README.md")
    with open(file_md_blocklist, "w") as file_output:
        file_output.write(intro)
    concat_md_category(blg, file_md_blocklist)


def gen_potential(blg, blocked, unblocked, num=10):
    """
    Generates a list of frequently blocked main domains

    :param blg: the main class
    :param blocked: blocked domains
    :param unblocked: unblocked domains
    :param num: the appearance frequency
    """
    extract = tldextract.TLDExtract(include_psl_private_domains=True)
    potential = []
    for domain in blocked:
        tld_extract = extract(domain)
        main_domain = tld_extract.domain + "." + tld_extract.suffix
        potential.append(main_domain)

    potential = [x for x in potential if x not in unblocked]
    potential = list(Counter(potential).most_common())
    potential = [k for k, v in potential if v > num]

    potential = [x + "\n" for x in potential]
    dir_potential = is_path(Path.joinpath(BASE, ".temp"))
    name = Path(blg.file_json).stem
    file_potential = Path.joinpath(dir_potential, f"{name}.txt")
    write_file(potential, file_potential)


def write_version(blg):
    """
    Write version number to a file

    :param blg: the main class
    """
    file_version = Path.joinpath(BASE, "version.txt")
    write_file(blg.header.version, file_version)


def process_sources(blg):
    """
    Processes the source json file for the category

    Gets content from the url for each individual source and,
    extracts blocked and unblocked domain from it and,
    appends it the unified blocked and unblocked domains for the category

    :param blg: the main class
    :return: unified blocked domains, unified unblocked domains
    """

    unified_blocked, unified_unblocked = [], []

    def worker(item):

        unprocessed = get_content(item[blg.i_key.url]).splitlines()
        if item[blg.i_key.is_abp]:
            blocked, unblocked = extract_abp(unprocessed)
        else:
            blocked, unblocked = extract_hosts(unprocessed, item[blg.i_key.is_noblock])
        blocked_not_wc, blocked_wc = separate_wildcard(blocked)
        blocked_not_wc = [x for x in blocked_not_wc if valid_domain(x)]
        unblocked_not_wc, unblocked_wc = separate_wildcard(unblocked)
        unblocked_not_wc = [x for x in unblocked_not_wc if valid_domain(x)]
        blocked = sorted(list(chain(blocked_not_wc, blocked_wc)))
        unblocked = sorted(list(chain(unblocked_not_wc, unblocked_wc)))
        unified_blocked.extend(blocked)
        unified_unblocked.extend(unblocked)
        item[blg.i_key.last_modified] = get_last_modified(item[blg.i_key.url])
        item[blg.i_key.num_blocked] = len(blocked)
        item[blg.i_key.num_unblocked] = len(unblocked)
        write_file(blg.data_json, blg.file_json)

    pool = ThreadPoolExecutor()
    with pool:
        pool.map(worker, blg.data_json[blg.j_key.sources])

    return unified_blocked, unified_unblocked


def remove_unblocked(blocked, unblocked):
    """
    Removes unblocked domains from blocked domains

    :param blocked: list of blocked domains
    :param unblocked: list of unblocked domains
    :return: list of blocked domains, statistics
    """
    stats = {}

    unblocked_cname, unblocked_no_cname = get_cname(unblocked)
    unblocked.extend(unblocked_cname)
    del unblocked_no_cname

    num_raw_blocked_domains = {"unprocessed": len(blocked)}
    stats.update(num_raw_blocked_domains)

    blocked = de_duplicate(blocked)
    unblocked = de_duplicate(unblocked)

    blocked = [item for item in blocked if item not in unblocked]

    num_blocked_domains = {"minus duplicates and false positives": len(blocked)}
    stats.update(num_blocked_domains)

    return blocked, stats


def remove_redundant(blocked, stats):
    """
    Removes sub-domains if main-domain is already in the list

    :param blocked: the input list of blocked domains
    :param stats: statistics
    :return: blocked domains without redundant subdomains, updated statistics
    """
    blocked, blocked_wc = separate_wildcard(blocked)

    main_domains = []
    extract = tldextract.TLDExtract(include_psl_private_domains=True)
    for domain in blocked:
        tld_extract = extract(domain)
        if not tld_extract.subdomain:
            main_domains.append(domain)

    pattern_if_sub = re.compile("|".join(f"(?:.*({p})$)" for p in main_domains))

    matched, unmatched = match_pattern(
        blocked, pattern_if_sub, "Scanning for redundant sub-domains"
    )
    del matched
    blocked = list(chain(unmatched, main_domains, blocked_wc))

    num_blocked_domains = {"minus redundant sub-domains": len(blocked)}
    stats.update(num_blocked_domains)

    return blocked, stats


def finalise(blg, blocked, unblocked, stats):
    """
    Runs functions for:
        generating statistics file from stats,
        generating blocklist from blocked domains,
        adding checksum to the generated blocklist,
        generating README.md for the blocklist category,
        generating/updating README.md for the entire blocklist and,
        generating a list of frequently blocked main domains
        generate a versions file

    :param blg: the main class
    :param blocked: list of blocked domains
    :param unblocked: list of unblocked domains
    :param stats: statistics
    """
    write_stats(blg, stats)
    file_blocklist = gen_lists(blg, blocked)
    gen_checksum(file_blocklist)
    gen_md_category(blg, stats)
    gen_md_blocklist(blg)
    gen_potential(blg, blocked, unblocked)
    write_version(blg)


BASE = Path(__file__).parents[1]


@dataclass
class BLGenerator:
    """
    Main class

    """

    sources = is_path(Path.joinpath(BASE, "sources"))

    #     if dir_empty(sources):
    #         get_default(
    #             sources,
    #             "general.json",
    #             "https://github.com/arapurayil/ABL/raw/master/sample_source.json",
    #         )

    lists = is_path(Path.joinpath(BASE, "lists"))

    list_sources = list(glob.glob(f"{sources}/*.json"))

    @dataclass
    class JSONKey:
        """
        Stores the keys for the source json file

        """

        title = "title"
        description = "description"
        sources = "sources"

    @dataclass
    class ItemKey:
        """
        Stores the keys for the individual source item in the source json file

        """

        title = "title"
        url = "url"
        is_abp = "is_abp"
        is_noblock = "is_noblock"
        num_blocked = "num_blocked"
        num_unblocked = "num_unblocked"
        last_modified = "last_modified"

    @dataclass
    class OutputFile:
        """
        Stores the names of the output files

        """

        domains = "domains.txt"
        blocklist = "blocklist.txt"
        stats = "stats.json"

    @dataclass
    class ListHeader:
        """
        Stores the values used in generating list header

        """

        title = "Adur Block List (ABL)"
        author = "Zachariah Arapurayil"
        version = (
            str(int(datetime.now().strftime("%y")) - 19)
            + "."
            + datetime.now().strftime("%m%d")
            + "."
            + datetime.now().strftime("%H%M")
        )
        expires = "4 hours"
        repo = "https://github.com/arapurayil/ABL"
        license = f"{repo}/license"
        issues = f"{repo}/issues"

    def __init__(self, file_json):
        """

        :param file_json: the category source json file
        """
        self.file_json = file_json
        self.data_json = read_file(file_json)
        self.category = Path(file_json).stem
        pre = "Anti-"
        post = " Addon"
        if self.category == "general":
            pre = post = ""
        self.list_title = f"{pre}{self.category.capitalize()}{post} List"
        self.dir = is_path(Path.joinpath(self.lists, self.category))
        self.j_key = self.JSONKey
        self.i_key = self.ItemKey
        self.f_out = self.OutputFile
        self.header = self.ListHeader


def main():
    """
    The main function.
    """
    ins = BLGenerator
    progress_bar = ProgIter(ins.list_sources, desc=f"Generating lists")
    category_done = []
    for i, file in enumerate(progress_bar):
        blg = ins(file)
        progress_bar.set_description(
            desc=f"Processing sources: {blg.category}", refresh=True
        )
        blocked, unblocked = process_sources(blg)
        if blocked:
            progress_bar.set_description(
                desc=f"Removing duplicates & false positives: {blg.category}",
                refresh=True,
            )
            blocked, stats = remove_unblocked(blocked, unblocked)
            progress_bar.set_description(
                desc=f"Removing redundant sub-domains: {blg.category}", refresh=True
            )
            blocked, stats = remove_redundant(blocked, stats)
            progress_bar.set_description(
                desc=f"Finalising: {blg.category}", refresh=True
            )
            finalise(blg, blocked, unblocked, stats)
            category_done.append(blg.category)

        if i == len(blg.list_sources) - 1:
            progress_bar.set_description(
                desc=f" Generated: {category_done} lists", refresh=True
            )


if __name__ == "__main__":
    main()
