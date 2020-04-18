import base64
import glob
import hashlib
import json
import textwrap
from collections import Counter
from concurrent.futures.process import ProcessPoolExecutor
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime
from functools import partial
from itertools import chain, repeat
from multiprocessing import cpu_count
from pathlib import Path
import inflect
import dns.resolver
import regex as re
import requests
from progiter import ProgIter
from tldextract import tldextract
from validators import domain as valid_domain

BASE = Path(__file__).parents[1]

INPUT_DIR = Path.joinpath(BASE, "sources")

OUTPUT_DIR = Path.joinpath(BASE, "lists")


class JSONKey(object):
    """
    Stores the keys for the source json file
    """

    title = "title"
    description = "description"
    sources = "sources"


class ITEMKey(object):
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


class ListInfo:
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
    last_modified = datetime.now().strftime("%d %b %Y %H:%M:%S IST")
    expires = "1 day"
    repo = "https://github.com/arapurayil/ABL"
    license = f"{repo}/license"
    issues = f"{repo}/issues"
    header = (
        f"repl_cmt Title: repl_title_cat\n"
        f"repl_cmt Author: {author}\n"
        f"repl_cmt Description: repl_desc_cat\n"
        f"repl_cmt Version: {version}\n"
        f"repl_cmt Last modified: {last_modified}\n"
        f"repl_cmt Expires: {expires} (update frequency)\n"
        f"repl_cmt\n"
        f"repl_cmt Repository: {repo}\n"
        f"repl_cmt You can find lists for other categories in the repo\n"
        f"repl_cmt This list is also available in repl_alt_list format\n"
        f"repl_cmt\n"
        f"repl_cmt Issues: {issues}\n"
        f"repl_cmt Please report false positives or unblocked domains through Issues\n"
        f"repl_cmt\n"
        f"repl_cmt Licence: {license}\n"
        f"repl_cmt-----------------------------------------"
        f"---------------------------------------------repl_cmt\n"
    )


class OutputFile:
    """
    Stores the names of the output files
    """

    domains = "domains.txt"
    blocklist = "blocklist.txt"
    stats = "stats.json"


class Generator(object):
    """
    Main class.
    """

    list_sources = list(glob.glob(f"{INPUT_DIR}/*.json"))

    def __init__(self, file_json):
        """

        :param file_json: the category source json file
        """
        self.file_json = file_json
        self.category = Path(file_json).stem
        self.data_json = read_file(file_json)
        self.j_key = JSONKey
        self.i_key = ITEMKey
        self.info = ListInfo
        self.dir_out = is_path(Path.joinpath(OUTPUT_DIR, self.category))
        self.f_out = OutputFile
        pre = "Anti-"
        post = " Add-on"
        if self.category == "general":
            pre = post = ""
        self.list_title = f"{pre}{self.category.capitalize()}{post} List"


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
        with open(path, encoding="utf-8") as file:
            data_json = json.load(file)
            return data_json
    else:
        with open(path, encoding="utf-8") as file:
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
    pattern_unblocked = re.compile("|".join(f"(?:{p})" for p in pattern_unblocked_list))

    content = [re.sub(pattern, "", item) for item in content]

    content_blocked = [
        item for item in content if re.match(r"^(\|\|).*\^", item, concurrent=True)
    ]
    content_blocked = [
        re.sub(pattern_blocked, "", item, concurrent=True) for item in content_blocked
    ]

    content_unblocked = [
        item for item in content if re.match(r"^(@@\|\|).*\^$", item, concurrent=True)
    ]
    content_unblocked = [
        re.sub(pattern_unblocked, "", item, concurrent=True)
        for item in content_unblocked
    ]

    blocked = [item for item in content_blocked if valid_domain(item)]
    unblocked = [item for item in content_unblocked if valid_domain(item)]

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

    content = [re.sub(pattern, "", item, concurrent=True) for item in content]

    domains = [item for item in content if valid_domain(item)]

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
    """
    Define tldextract
    :param domain: domain to extract tld
    :return: extract
    """
    extract = tldextract.TLDExtract(include_psl_private_domains=True)
    return extract(domain)


def gen_lists(blg, blocked):
    """
    Generates blocklist files in ABP format and domains format
    :param blg: the main class
    :param blocked: the blocked domains
    :return: the path of the blocklist file in ABP format
    """
    abp_pre_header = "[Adblock Plus 2.0]\n"
    list_title = f"{blg.info.title} - {blg.list_title}"

    header = (
        str(blg.info.header)
        .replace("repl_title_cat", list_title)
        .replace("repl_desc_cat", blg.data_json[blg.j_key.description])
    )

    file_domains = is_path(Path.joinpath(blg.dir_out, blg.f_out.domains))
    file_blocklist = is_path(Path.joinpath(blg.dir_out, blg.f_out.blocklist))
    blocked_domains = [x + "\n" for x in sorted(blocked)]

    with open(file_domains, "w", encoding="utf-8") as file:
        file.write(header.replace("repl_cmt", "#").replace("repl_alt_list", "ABP"))
        for line in blocked_domains:
            file.write(line)

    blocklist = [x.replace(x, f"||{x}^\n") for x in sorted(blocked)]
    with open(file_blocklist, "w", encoding="utf-8") as file:
        file.write(abp_pre_header)
        file.write(header.replace("repl_cmt", "!").replace("alt_list", "domains"))
        for line in blocklist:
            file.write(line)

    return file_blocklist


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

    with open(file_blocklist, encoding="utf8") as file:
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
    write_file(blg.data_json, blg.file_json)

    def data_md():
        def section_one():
            heading_h1 = f"""# The {blg.list_title}"""
            desc = f"""{textwrap.fill(blg.data_json[blg.j_key.description])}"""
            content_section_one = chain("\n", heading_h1, "\n\n", desc, "\n")
            return content_section_one

        def section_two():
            heading_h2 = f"## Sources for the {blg.list_title}"
            tbl = []

            tbl_c1 = "#"
            tbl_c2 = "Title"
            tbl_c3 = "Blocked"
            tbl_c4 = "Unblocked"
            len_c1, len_c2, len_c3, len_c4 = (
                len(":---"),
                len(":---"),
                len(":---"),
                len(":---"),
            )
            if len_c1 < len(tbl_c1):
                len_c1 = len(tbl_c1)
            if len_c2 < len(tbl_c2):
                len_c2 = len(tbl_c2)
            if len_c3 < len(tbl_c3):
                len_c3 = len(tbl_c3)
            if len_c4 < len(tbl_c4):
                len_c4 = len(tbl_c4)

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
                tbl_contents = f"| {str(index + 1).zfill(2).ljust(len_c1)} | {str(f'[{key[blg.i_key.title]}]({key[blg.i_key.url]})').ljust(len_c2)} | {str(key[blg.i_key.num_blocked]).ljust(len_c3)} | {str(key[blg.i_key.num_unblocked]).ljust(len_c4)} |\n"

                tbl.append(tbl_contents)

            content_section_two = chain("\n", heading_h2, "\n\n", tbl)
            return content_section_two

        def section_three():
            heading_h2 = f"### Statistics for the {blg.list_title}"
            tbl = []
            tbl_c1 = "Domains"
            tbl_c2 = "Blocked"

            len_c1, len_c2 = (len(":---"), len(":---"))

            if len_c1 < len(tbl_c1):
                len_c1 = len(tbl_c1)
            if len_c2 < len(tbl_c2):
                len_c2 = len(tbl_c2)

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

    file_md_category = is_path(Path.joinpath(blg.dir_out, "README.md"))
    write_file(data_md(), file_md_category)


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
    file_potential = Path.joinpath(dir_potential, f"{blg.category}.txt")
    write_file(potential, file_potential)


def write_version(blg):
    """
    Write version number to a file
    :param blg: the main class
    """
    file_version = Path.joinpath(BASE, "version.txt")
    write_file(blg.info.version, file_version)


def concat_md_category(out_file):
    """
    Concatenate all the category README.md files
    :param out_file: README.md file for ABL
    """
    for file in glob.glob(f"{OUTPUT_DIR}/*/*.md"):
        with open(file, encoding="utf-8") as file_input, open(
            out_file, "a", encoding="utf-8"
        ) as file_output:
            for line in file_input:
                if re.match(r"^(#|##|###)\s", line):
                    line = re.sub(r"^#", r"##", line)
                file_output.write(line)


def process_sources(blg):
    """
    Processes the source json file for the category
    Gets content from the url for each individual source and,
    extracts blocked and unblocked domain from it and,
    appends it the unified blocked and unblocked domains for the category
    :param blg: the main class
    :return: unified blocked domains, unified unblocked domains
    """

    all_blocked, all_unblocked = [], []

    def worker(item):

        unprocessed = get_content(item[blg.i_key.url]).splitlines()
        if item[blg.i_key.is_abp]:
            pass
            blocked, unblocked = extract_abp(unprocessed)
        else:
            blocked, unblocked = extract_hosts(unprocessed, item[blg.i_key.is_noblock])

        all_blocked.extend(blocked)
        all_unblocked.extend(unblocked)
        item[blg.i_key.last_modified] = get_last_modified(item[blg.i_key.url])
        item[blg.i_key.num_blocked] = len(blocked)
        item[blg.i_key.num_unblocked] = len(unblocked)
        write_file(blg.data_json, blg.file_json)

    pool = ThreadPoolExecutor()
    with pool:
        pool.map(worker, blg.data_json[blg.j_key.sources])

    return all_blocked, all_unblocked


def remove_duplicates_false(blocked, unblocked):
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

    blocked = list(set(blocked) - set(unblocked))

    num_blocked_domains = {"minus duplicates and false positives": len(blocked)}
    stats.update(num_blocked_domains)

    return blocked, stats


def tld_extract_worker(domain):
    if not extract_tld(domain).subdomain:
        return domain


def match_worker(pattern, item):
    return re.findall(pattern, item, concurrent=True)


def remove_redundant(blocked, stats):
    """
    Removes sub-domains if main-domain is already in the list
    :param blocked: the input list of blocked domains
    :param stats: statistics
    :return: blocked domains without redundant subdomains, updated statistics
    """

    pool = ProcessPoolExecutor()
    with pool:
        main_domains = list(
            ProgIter(
                pool.map(tld_extract_worker, blocked, chunksize=100),
                desc="Main",
                total=len(blocked),
                chunksize=100,
            )
        )

    sub_domains = list(set(blocked) - set(main_domains))
    main_domains = list(set(main_domains))

    pattern_if_sub = re.compile(
        "|".join(f"(?:.*" + r"\b" + f"{p}" + r"\b" + f"$)" for p in main_domains),
        re.M | re.I | re.V1,
    )

    string_sub_domains = "\n".join(sub_domains)
    function_match = partial(match_worker, pattern_if_sub)
    pool = ProcessPoolExecutor()
    with pool:
        matched_subdomains = list(
            ProgIter(
                pool.map(function_match, string_sub_domains, chunksize=100),
                desc="Sub",
                total=len(string_sub_domains),
                chunksize=100,
            )
        )

    unmatched_subdomains = list(set(sub_domains) - set(matched_subdomains))
    blocked = list(chain(unmatched_subdomains, main_domains))

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
    file_blocklist = gen_lists(blg, blocked)
    gen_checksum(file_blocklist)
    gen_md_category(blg, stats)
    gen_potential(blg, blocked, unblocked)
    write_version(blg)


def gen_md_blocklist(ins):
    """
    Generate README.md for ABL from category README.md files
    :param ins: the main class
    """
    file_about = is_path(Path.joinpath(BASE, "ABOUT.md"))
    about = read_file(file_about, data_type="str")
    if not about:
        about = f"\n# {ListInfo.title}\n"

    def section_one():
        list_titles = []
        formats = ["domains", "ABP block list"]
        count = 0
        lists = "lists"
        for file in ins.list_sources:
            blg = ins(file)
            list_titles.append(blg.list_title)
            count += 1
        if count == 1:
            count = "a"
            lists = "list"
        else:
            count = inflect.engine().number_to_words(count)
        intro = (
            f"This project generates {count} {lists}: `{(', '.join(list_titles))}`\n\n"
            f"{lists.capitalize()} are generated in two formats: `{(', '.join(formats))}`\n\n"
        )
        return intro

    def section_two():
        tbl = []
        tbl_c1 = "LISTS NAME"
        len_c1 = len("---")
        tbl_c2 = "DESCRIPTION"
        len_c2 = len("---")
        tbl_c3 = "DOMAINS LIST"
        len_c3 = len("---")
        tbl_c4 = "ABP BLOCKLIST"
        len_c4 = len("---")

        for file in ins.list_sources:
            blg = ins(file)
            domains_link = (
                f"[Link]({blg.info.repo}/raw/master/lists/{blg.category}/domains.txt)"
            )
            blocklist_link = (
                f"[Link]({blg.info.repo}/raw/master/lists/{blg.category}/blocklist.txt)"
            )

            if len(str({blg.list_title})) > len_c1:
                len_c1 = len(str({blg.list_title}))
            if len(str(blg.data_json[blg.j_key.description])) > len_c2:
                len_c2 = len(str(blg.data_json[blg.j_key.description]))
            if len(str(domains_link)) > len_c3:
                len_c3 = len(str(domains_link))
            if len(str(blocklist_link)) > len_c4:
                len_c4 = len(str(blocklist_link))

        tbl_title = (
            f"| {tbl_c1.center(len_c1)} | {tbl_c2.center(len_c2)} | {tbl_c3.center(len_c3)} | {tbl_c4.center(len_c4)} |\n"
            f"| {'---'.center(len_c1, '-')} | {'---'.center(len_c2, '-')} | {'---'.center(len_c3, '-')} | {'---'.center(len_c4, '-')} |\n"
        )
        tbl.append(tbl_title)

        for file in ins.list_sources:
            blg = ins(file)
            domains_link = (
                f"[Link]({blg.info.repo}/raw/master/lists/{blg.category}/domains.txt)"
            )
            blocklist_link = (
                f"[Link]({blg.info.repo}/raw/master/lists/{blg.category}/blocklist.txt)"
            )
            tbl_contents = f"| {blg.list_title.center(len_c1)} | {str(blg.data_json[blg.j_key.description]).center(len_c2)} | {str(domains_link.center(len_c3))} | {str(blocklist_link.center(len_c4))} |\n"
            tbl.append(tbl_contents)

        return tbl

    file_md_blocklist = Path.joinpath(BASE, "README.md")

    s_1 = section_one()
    s_2 = section_two()
    with open(file_md_blocklist, "w", encoding="utf-8") as file_output:
        file_output.write(about)
        file_output.writelines(s_1)
        file_output.writelines(s_2)
    concat_md_category(file_md_blocklist)


def main():
    """
    The main function.
    """
    ins = Generator
    progress_bar = ProgIter(ins.list_sources, desc=f"Generating lists")
    category_done = []
    for i, file in enumerate(progress_bar):
        blg = ins(file)
        progress_bar.set_description(
            desc=f"Processing sources for category: {blg.category}"
        )
        blocked, unblocked = process_sources(blg)

        if blocked:
            progress_bar.set_description(
                desc=f"Removing duplicates & false positives for category: {blg.category}"
            )
            blocked, stats = remove_duplicates_false(blocked, unblocked)
            progress_bar.set_description(
                desc=f"Removing redundant sub-domains for category: {blg.category}"
            )
            blocked, stats = remove_redundant(blocked, stats)
            progress_bar.set_description(desc=f"Finalising: {blg.category}")
            finalise(blg, blocked, unblocked, stats)
            category_done.append(blg.category)
        if i == len(blg.list_sources) - 1:
            progress_bar.set_description(desc=f" Generated: {category_done} lists")
    gen_md_blocklist(ins)


if __name__ == "__main__":
    main()
