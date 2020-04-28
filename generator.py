"""
ABL Generator

Creates compiled blocklists in Domains and ABP Filter List format
Uses json files in a specific format containing list of well-known blocklists
The source lists should be in Domains/Hosts ot ABP Filter List format
This script only supports ABP filters that are compatible with AdGuard Home
Duplicates and subdomains, if its registered domain is already blocked, are removed
The generated lists are best used with AdGuard Home orDNSCrypt 2
or any other DNS level blocking solution
"""
from base64 import b64encode
from collections import namedtuple, Counter
from concurrent.futures.process import ProcessPoolExecutor
from concurrent.futures.thread import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from glob import glob
from hashlib import md5
from itertools import chain, repeat
from json import load, loads, dump
from pathlib import Path
from textwrap import fill

import markdown_strings
from dns import resolver, exception as dns_exception
from progiter import ProgIter
from regex import regex as re
from requests import Session
from requests.adapters import HTTPAdapter, Retry
from tldextract import tldextract
from validators import domain as valid_domain


@dataclass
class DirPath:
    """For the source json file."""

    base = Path(__file__).parents[0]
    input = Path.joinpath(base, "sources")
    output = Path.joinpath(base, "lists")
    temp = Path.joinpath(base, ".temp")


@dataclass
class JsonKey:
    """Keys for the source json file."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@dataclass
class ItemKey:
    """Keys for the individual source items in the source json file"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@dataclass
class ListInfo:
    """Values for the list header."""

    title = "Adur Block List (ABL)"
    author = "Zachariah Arapurayil"
    version = (
        str(int(datetime.now().strftime("%Y")) - 2019)
        + "."
        + datetime.now().strftime("%m")
        + "."
        + datetime.now().strftime("%d")
    )
    last_modified = datetime.now().strftime("%d %b %Y %H:%M:%S IST")
    expires = "1 day"
    repo = "https://github.com/arapurayil/ABL"

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@dataclass
class OutputFile:
    """Output file names."""

    domains = "blocked_domains.txt"
    abp_filter = "filter_list.txt"


@dataclass
class ListGenerator:
    """The main class."""

    j_key = JsonKey(title="title", desc="description", sources="sources",)
    i_key = ItemKey(
        title="title",
        url="url",
        desc="description",
        abp_format="abp_format",
        false_positive="false_positive",
        num_blocked="num_blocked",
        num_unblocked="num_unblocked",
        last_modified="last_modified",
    )
    info = ListInfo(
        header=(
            f"repl_cmt Title: repl_cat_title\n"
            f"repl_cmt Author: {ListInfo.author}\n"
            f"repl_cmt Description: repl_cat_desc\n"
            f"repl_cmt Version: {ListInfo.version}\n"
            f"repl_cmt Last modified: {ListInfo.last_modified}\n"
            f"repl_cmt Expires: {ListInfo.expires} (update frequency)\n"
            f"repl_cmt\n"
            f"repl_cmt Repository: {ListInfo.repo}\n"
            f"repl_cmt You can find lists for other categories in the repo\n"
            f"repl_cmt This list is also available in repl_alt_list format\n"
            f"repl_cmt\n"
            f"repl_cmt Issues: {ListInfo.repo}/issues\n"
            f"repl_cmt Please report false positives or unblocked domains through Issues\n"
            f"repl_cmt\n"
            f"repl_cmt Licence: {ListInfo.repo}/license\n"
            f"repl_cmt-----------------------------------------"
            f"---------------------------------------------repl_cmt\n"
        ),
    )

    def __init__(self, file_json, **kwargs):
        self.file_json = file_json
        self.category = Path(file_json).stem
        self.data_json = read_file(file_json)
        self.dir_cat = Path.joinpath(DirPath.output, Path(file_json).stem)
        self.__dict__.update(kwargs)


def is_path(path):
    """Creates file/directory if path doesn't exist and/or returns path."""
    if Path(path).suffix:
        if not Path(path).exists():
            if not Path(path).parents[0].exists():
                Path(path).parents[0].mkdir(parents=True, exist_ok=True)
            Path(path).open("x", encoding="utf-8").close()
        return Path(path)
    if not Path(path).exists():
        Path(path).mkdir(parents=True, exist_ok=True)
    return Path(path)


def read_file(path, data_type="list"):
    """Reads a file and returns its contents."""
    if Path(path).suffix == ".json":
        with open(path, encoding="utf-8") as file:
            return load(file)
    else:
        with open(path, encoding="utf-8") as file:
            return file.readlines() if data_type == "list" else file.read()


def write_file(data, path):
    """Writes a file with the given data."""
    if Path(path).suffix == ".json":
        if isinstance(data, str):
            data = loads(data)
        with open(path, "w", encoding="utf-8") as file:
            file.seek(0)
            dump(data, file, indent=4)
            file.truncate()
    else:
        with open(path, "w", encoding="utf-8") as output_file:
            for line in data:
                output_file.write(line)


def get_response(url):
    """Fetches response headers for the URL."""
    retries = Retry(
        total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
    )
    http = Session()
    http.mount("https://", HTTPAdapter(max_retries=retries))
    http.headers.update(
        {
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 (Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0",
        }
    )

    return http.get(url, allow_redirects=True, timeout=30)


def get_content(url):
    """Fetches content for the URL."""
    return get_response(url).content.decode("utf-8")


def get_last_modified(url):
    """Fetches the last-modified tag/etag of the URL."""
    if "last-modified" not in get_response(url).headers:
        if "etag" in get_response(url).headers:
            return get_response(url).headers["etag"]
        return False
    return get_response(url).headers["last-modified"]


def dns_resolver():
    """Defines the resolver with custom values."""
    custom_dns_resolver = resolver.Resolver()
    custom_dns_resolver.nameservers = [
        "8.8.8.8",
        "2001:4860:4860::8888",
        "8.8.4.4",
        "2001:4860:4860::8844",
    ]
    custom_dns_resolver.lifetime = custom_dns_resolver.timeout = 5
    return custom_dns_resolver


def worker_get_cname(item):
    """Worker for get_cname via ThreadPoolExecutor."""
    try:
        answer = dns_resolver().query(item, "CNAME")
        for cname_val in answer:
            return str(cname_val.target).rstrip(".")
    except (resolver.NoAnswer, resolver.NXDOMAIN, dns_exception.Timeout):
        pass


def get_cname(domains):
    """Fetches CNAME of a list of domains."""
    with ThreadPoolExecutor() as pool:
        domains_cname = {
            x for x in pool.map(worker_get_cname, domains) if x is not None
        }
    return domains_cname


def extract_abp(content):
    """Extracts blocked and unblocked domains from ABP style content."""
    pattern_unsupported = re.compile(r"\S+(?>\/|\=)\S+", re.V1)
    pattern_if_blocked = re.compile(
        r"^\|\|.+\^(?>$|.+(?:"
        r"\bfirst-party\b|"
        r"\b1p\b|"
        r"\bthird-party\b|"
        r"\b3p\b|"
        r"\bdocument\b|"
        r"\ball\b|"
        r"\bpopup\b"
        r"))",
        re.V1,
    )
    pattern_clean_blocked_list = [
        r"^\|\|",
        r"\^($|.+(?>"
        r"\bfirst-party\b|"
        r"\b1p\b|"
        r"\bthird-party\b|"
        r"\b3p\b|\bdocument\b|"
        r"\ball\b|"
        r"\bpopup\b|"
        r"\S+))",
    ]
    pattern_clean_blocked = re.compile(
        "|".join(f"(?:{p})" for p in pattern_clean_blocked_list), re.V1
    )
    blocked = [
        x
        for x in content
        if re.match(pattern_if_blocked, x, concurrent=True)
        and not re.match(pattern_unsupported, x, concurrent=True)
    ]
    blocked = [re.sub(pattern_clean_blocked, "", x, concurrent=True) for x in blocked]
    pattern_if_unblocked = re.compile(r"@@\|\|.+\^$")
    unblocked = [
        x
        for x in content
        if re.match(pattern_if_unblocked, x, concurrent=True)
        and not re.match(pattern_unsupported, x, concurrent=True)
    ]
    false_positives = [x.replace("@@||", "").replace("^", "") for x in unblocked]
    return blocked, unblocked, false_positives


def extract_hosts(content, is_false):
    """Extracts blocked or unblocked domains from hosts/domains style content."""
    pattern_list = [
        r"(?>\#|\!|\s+\#|\s+\!).*",
        r".*\blocalhost\b.*",
        r"^\d*\.\d*\.\d*\.\d*\s*(?>\s|www\.|m\.)",
        r"^(?>www\.|m\.)",
    ]
    pattern = re.compile("|".join(f"(?:{p})" for p in pattern_list), re.V1)
    domains = [re.sub(pattern, "", x, concurrent=True) for x in content]
    domains = [x for x in domains if valid_domain(x)]
    blocked, unblocked, false_positives = [], [], []
    if is_false:
        false_positives = domains
    else:
        blocked = domains
    return blocked, unblocked, false_positives


def worker_process_sources(item, blg):
    """Worker for process_sources via ThreadPoolExecutor."""
    progress_bar = ProgIter(total=1, desc=f"Processing — {item[blg.i_key.title]}")
    with progress_bar:
        unprocessed = get_content(item[blg.i_key.url]).splitlines()
        if item[blg.i_key.abp_format]:
            blocked, unblocked, false_positives = extract_abp(unprocessed)
        else:
            blocked, unblocked, false_positives = extract_hosts(
                unprocessed, item[blg.i_key.false_positive]
            )
        item[blg.i_key.last_modified] = get_last_modified(item[blg.i_key.url])
        item[blg.i_key.num_blocked] = len(blocked)
        item[blg.i_key.num_unblocked] = len(unblocked)
        write_file(blg.data_json, blg.file_json)
        progress_bar.update()
        progress_bar.set_description(f"Processed — {item[blg.i_key.title]}")
    return blocked, unblocked, false_positives


def process_sources(blg):
    """Processes the source json file for the category
    Fetches the content for the url for each individual source and,
    extracts blocked and unblocked domains from it and,
    appends it the unified blocked and unblocked domains for the category.
    """
    blg.data_json[blg.j_key.sources] = sorted(
        blg.data_json[blg.j_key.sources], key=lambda x: x[blg.i_key.title].upper()
    )
    with ThreadPoolExecutor() as pool:
        blocked, unblocked, false_positives = zip(
            *pool.map(
                worker_process_sources, blg.data_json[blg.j_key.sources], repeat(blg),
            )
        )

    blocked = chain.from_iterable(blocked)
    unblocked = chain.from_iterable(unblocked)
    false_positives = chain.from_iterable(false_positives)
    return blocked, unblocked, false_positives


def remove_duplicates_false(blocked, false_positive):
    """Removes duplicates and false positives from blocked domains."""
    stats = {}
    false_positive = set(false_positive)
    false_positive_cname = get_cname(false_positive)
    false_positive.update(false_positive_cname)
    blocked = list(blocked)
    num_raw_blocked_domains = {"unprocessed": len(blocked)}
    stats.update(num_raw_blocked_domains)
    blocked = set(blocked) - set(false_positive)
    num_blocked_domains = {"minus duplicates and false positives": len(blocked)}
    stats.update(num_blocked_domains)
    return blocked, stats


def extract_tld(domain):
    """Defines tldextract to include psl private domains."""
    extract = tldextract.TLDExtract(include_psl_private_domains=True)
    return extract(domain)


def worker_return_main_domain(domain):
    """Worker for remove_redundant via ProcessPoolExecutor
     to get main domains.
     """
    if not extract_tld(domain).subdomain:
        return domain
    return None


def worker_extract_registered_domain(domain):
    """Worker for remove_redundant via ProcessPoolExecutor
     to get redudant subdomains from main domains.
     """
    return extract_tld(domain).registered_domain


def worker_unmatched_item(item, pattern):
    """Worker for remove_redundant via ThreadPoolExecutor
     to get unmatched subdomains from subdomains.
     """
    if not re.match(pattern, item, concurrent=True):
        return item
    return None


def remove_redundant(blocked, stats, blg):
    """Removes sub-domains if main-domain is already in the list."""
    file_main_domains = is_path(
        Path.joinpath(DirPath.temp, f"main_domains_{blg.category}.txt")
    )
    cached_main_domains = {x.strip() for x in read_file(file_main_domains)}
    if cached_main_domains:
        identified_main_domains = blocked & cached_main_domains
        domains_to_check = blocked - identified_main_domains
    else:
        domains_to_check = blocked
        identified_main_domains = None
    with ProcessPoolExecutor() as pool:
        main_domains = set(
            ProgIter(
                pool.map(worker_return_main_domain, domains_to_check, chunksize=100),
                desc=f"Fetching main-domains — {blg.category}",
                total=len(domains_to_check),
                chunksize=100,
            )
        )
    if identified_main_domains:
        main_domains = main_domains | identified_main_domains
    if None in main_domains:
        main_domains.remove(None)
    sub_domains = blocked - main_domains
    with ProcessPoolExecutor() as pool:
        sub_main_domains = set(
            ProgIter(
                pool.map(worker_extract_registered_domain, sub_domains, chunksize=100),
                desc=f"Extracting registered-domains from sub-domains — {blg.category}",
                total=len(sub_domains),
                chunksize=100,
            )
        )
    if None in sub_main_domains:
        sub_main_domains.remove(None)
    redundant_sub_main_domains = main_domains & sub_main_domains
    if redundant_sub_main_domains != "":
        pattern = re.compile(
            r".+(?>"
            + "|".join(
                r"\b" + f"{re.escape(p)}" + r"\b" for p in redundant_sub_main_domains
            )
            + r")$",
            re.V1,
        )
        with ThreadPoolExecutor() as pool:
            unmatched_subdomains = set(
                ProgIter(
                    pool.map(worker_unmatched_item, sub_domains, repeat(pattern)),
                    desc=f"Matching redundant sub-domains — {blg.category}",
                    total=len(sub_domains),
                )
            )
        if None in unmatched_subdomains:
            unmatched_subdomains.remove(None)
        blocked = unmatched_subdomains | main_domains
        num_blocked_domains = {"minus redundant sub-domains": len(blocked)}
        stats.update(num_blocked_domains)
        write_file("\n".join(main_domains), file_main_domains)
    return blocked, main_domains, stats


def gen_checksum(file_blocklist):
    """Not necessary: ABP no longer requires checksum validation.
    adapted from https://github.com/adblockplus/adblockplus/blob/master/addChecksum.py
    """
    checksum_pattern = re.compile(
        r"^\s*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n", re.I | re.M
    )

    def add_checksum(in_data):
        """Adds checksum."""
        checksum = calculate_checksum(in_data)
        re.sub(checksum_pattern, "", in_data)
        return re.sub(r"(\r?\n)", r"\1! Checksum: %s\1" % checksum, in_data, 1)

    def calculate_checksum(in_data):
        """Calculate checksum for the filterlist file."""
        md5().update(normalize(in_data).encode("utf-8"))
        return b64encode(md5().digest()).decode("utf-8").rstrip("=")

    def normalize(in_data):
        """Cleans the filterlist file."""
        re.sub(r"\r", "", in_data)
        re.sub(r"\n+", "\n", in_data)
        return re.sub(checksum_pattern, "", in_data)

    with open(file_blocklist, encoding="utf-8") as file:
        read_data = file.read()
    data = add_checksum(read_data)
    write_file(data, file_blocklist)


def gen_lists(blg, blocked, unblocked):
    """Generates blocklist files in ABP format and domains format."""
    blocked = sorted(blocked)
    unblocked = sorted(unblocked)
    list_title = f"{blg.info.title} - {blg.data_json[blg.j_key.title]}"
    header = (
        str(blg.info.header)
        .replace("repl_cat_title", list_title)
        .replace("repl_cat_desc", blg.data_json[blg.j_key.desc])
    )
    file_domains = is_path(Path.joinpath(blg.dir_cat, OutputFile.domains))
    file_filter = is_path(Path.joinpath(blg.dir_cat, OutputFile.abp_filter))
    blocked_domains = "\n".join(blocked)
    with open(file_domains, "w", encoding="utf-8") as file:
        file.write(header.replace("repl_cmt", "#").replace("repl_alt_list", "ABP"))
        for line in blocked_domains:
            file.write(line)
    blocked = [x.replace(x, f"||{x}^\n") for x in blocked]
    unblocked = "\n".join(unblocked)
    with open(file_filter, "w", encoding="utf-8") as file:
        abp_pre_header = "[Adblock Plus 2.0]\n"
        file.write(abp_pre_header)
        file.write(header.replace("repl_cmt", "!").replace("alt_list", "domains"))
        for line in blocked:
            file.write(line)
        for line in unblocked:
            file.write(line)
    gen_checksum(file_filter)


def md_category_section_main(blg, stats):
    """Generates the main section of the category README.md file."""
    value_percentage = float(
        (
            (int(stats["unprocessed"]) - int(stats["minus redundant sub-domains"]))
            / int(stats["unprocessed"])
        )
        * 100
    )
    main_title = markdown_strings.header(f"{blg.data_json[blg.j_key.title]}", 1)
    main_desc = markdown_strings.bold(f"{fill(blg.data_json[blg.j_key.desc])}")
    info_list = [
        f"Sources: {len(blg.data_json[blg.j_key.sources])}",
        f"""Unprocessed domains: {stats["unprocessed"]}""",
        f"""Blocked domains: {stats["minus redundant sub-domains"]}""",
    ]
    info_add = markdown_strings.unordered_list(info_list)
    string_bold = (
        f"ABL - {blg.data_json[blg.j_key.title]} is {value_percentage:.2f}% lighter"
    )
    sub_desc = (
        f"\nBy removing duplicates, false-positives and redundant sub-domains "
        f"the {markdown_strings.bold(string_bold)} than its combined sources"
    )
    return [main_title, main_desc, info_add, sub_desc]


def md_category_section_table(blg):
    """Generates the table for the category README.md file."""
    tbl_col_tup = namedtuple("tbl_col_tup", "c1, c2, c3, c4, c5")
    tbl_col_arr = [
        "#",
        "Title",
        "Description",
        "Blocked domains",
        "Unblocked domains",
    ]
    tbl_col = tbl_col_tup(*tbl_col_arr)
    tbl_pad_arr = [
        len("---"),
        len(tbl_col.c2),
        len(tbl_col.c3),
        len(tbl_col.c4),
        len(tbl_col.c5),
    ]
    tbl_pad = tbl_col_tup(*tbl_pad_arr)
    for index, key in enumerate(blg.data_json[blg.j_key.sources]):
        if len(str({index + 1}).zfill(2)) > tbl_pad.c1:
            tbl_pad_arr[0] = len(str({index + 1}).zfill(2)) + 2
        if len(str(f"[{key[blg.i_key.title]}]({key[blg.i_key.url]})")) > tbl_pad.c2:
            tbl_pad_arr[1] = (
                len(str(f"[{key[blg.i_key.title]}]({key[blg.i_key.url]})")) + 2
            )
        if len(str({key[blg.i_key.desc]})) > tbl_pad.c3:
            tbl_pad_arr[2] = len(str({key[blg.i_key.desc]})) + 2
        if len(str({key[blg.i_key.num_blocked]})) > tbl_pad.c4:
            tbl_pad_arr[3] = len(str({key[blg.i_key.num_blocked]})) + 2
        if len(str({key[blg.i_key.num_unblocked]})) > tbl_pad.c5:
            tbl_pad_arr[4] = len(str({key[blg.i_key.num_unblocked]})) + 2
        tbl_pad = tbl_col_tup(*tbl_pad_arr)
    table_title_row = markdown_strings.table_row(
        [tbl_col.c1, tbl_col.c2, tbl_col.c3, tbl_col.c4, tbl_col.c5],
        [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
    )
    table_delimiter = markdown_strings.table_delimiter_row(
        5, column_lengths=[tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
    )
    table_contents = []
    for index, key in enumerate(blg.data_json[blg.j_key.sources]):
        link = markdown_strings.link(key[blg.i_key.title], key[blg.i_key.url])
        row = markdown_strings.table_row(
            [
                str(index + 1).zfill(2),
                link,
                key[blg.i_key.desc],
                key[blg.i_key.num_blocked],
                key[blg.i_key.num_unblocked],
            ],
            [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
        )
        table_contents.append(row)
    return [table_title_row, table_delimiter, "\n".join(table_contents)]


def gen_md_category(blg, stats):
    """Generates README.md for the blocklist category."""
    section = [
        "\n".join(md_category_section_main(blg, stats)),
        "\n".join(md_category_section_table(blg)),
    ]
    data_md = "\n\n".join(section)

    file_md_category = is_path(Path.joinpath(blg.dir_cat, "README.md"))
    write_file(data_md, file_md_category)


def gen_potential(blg, blocked, false_positives, num=10):
    """Generates a list of frequently blocked main domains."""
    file_potential = is_path(
        Path.joinpath(DirPath.temp, f"potential_{blg.category}.txt")
    )
    cached_potential = {x.strip() for x in read_file(file_potential)}
    domains_to_check = blocked - cached_potential if cached_potential else blocked
    with ProcessPoolExecutor() as pool:
        main_domains = pool.map(
            worker_extract_registered_domain, domains_to_check, chunksize=100
        )
    potential = [x for x in main_domains if x not in false_positives]
    potential = Counter(potential).most_common()
    potential = {k for k, v in potential if v > num}
    potential |= cached_potential
    potential = "\n".join(filter(None, potential))

    write_file(potential, file_potential)


def write_version(blg):
    """Writes version number to a file."""
    file_version = Path.joinpath(DirPath.base, "version.txt")
    write_file(blg.info.version, file_version)


def finalise(blg, blocked, unblocked, false_positives, stats):
    """Finalises the lists by,
        generating blocklists,
        generating README.md for the blocklist category,
        generating a list of potential domains to be blocked and,
        generating a file with version info.
    """
    gen_lists(blg, blocked, unblocked)
    gen_md_category(blg, stats)
    gen_potential(blg, blocked, false_positives)
    write_version(blg)


def md_blocklist_section_table(list_sources):
    """The table for the blocklist README.md file."""
    tbl_col_tup = namedtuple("tbl_col_tup", "c1, c2, c3, c4, c5")
    tbl_col_arr = ["#", "TITLE", "DESCRIPTION", "DOMAINS LIST", "ABP FILTER LIST"]
    tbl_col = tbl_col_tup(*tbl_col_arr)
    tbl_pad_arr = [
        len("---"),
        len(tbl_col.c2),
        len(tbl_col.c3),
        len(tbl_col.c4),
        len(tbl_col.c5),
    ]
    table_contents = []
    tbl_pad = tbl_col_tup(*tbl_pad_arr)
    for index, file in enumerate(list_sources):
        blg = ListGenerator(file_json=file,)
        domain_list_link = markdown_strings.link(
            "Link",
            f"{blg.info.repo}/raw/master/lists/{blg.category}/{OutputFile.domains}",
        )
        filter_list_link = markdown_strings.link(
            "Link",
            f"{blg.info.repo}/raw/master/lists/{blg.category}/{OutputFile.abp_filter}",
        )
        if len(str(index + 1).zfill(2)) > tbl_pad.c1:
            tbl_pad_arr[0] = len(str(index + 1).zfill(2)) + 2
        if len(str(blg.data_json[blg.j_key.title])) > tbl_pad.c2:
            tbl_pad_arr[1] = len(str(blg.data_json[blg.j_key.title])) + 2
        if len(str(blg.data_json[blg.j_key.desc])) > tbl_pad.c3:
            tbl_pad_arr[2] = len(str(blg.data_json[blg.j_key.desc])) + 2
        if len(str(domain_list_link)) > tbl_pad.c4:
            tbl_pad_arr[3] = len(str(domain_list_link)) + 2
        if len(str(filter_list_link)) > tbl_pad.c5:
            tbl_pad_arr[4] = len(str(filter_list_link)) + 2
        tbl_pad = tbl_col_tup(*tbl_pad_arr)
    for index, file in enumerate(list_sources):
        blg = ListGenerator(file_json=file,)
        domain_list_link = markdown_strings.link(
            "Link",
            f"{blg.info.repo}/raw/master/lists/{blg.category}/{OutputFile.domains}",
        )
        filter_list_link = markdown_strings.link(
            "Link",
            f"{blg.info.repo}/raw/master/lists/{blg.category}/{OutputFile.abp_filter}",
        )
        row = markdown_strings.table_row(
            [
                str(index + 1).zfill(2),
                str(blg.data_json[blg.j_key.title]),
                str(blg.data_json[blg.j_key.desc]),
                str(domain_list_link),
                str(filter_list_link),
            ],
            [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
        )
        table_contents.append(row)
    table_delimiter = markdown_strings.table_delimiter_row(
        5, column_lengths=[tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5]
    )
    table_title_row = markdown_strings.table_row(
        [tbl_col.c1, tbl_col.c2, tbl_col.c3, tbl_col.c4, tbl_col.c5],
        [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
    )
    return [table_title_row, table_delimiter, "\n".join(table_contents)]


def concat_md_category(out_file):
    """Concatenate category README.md files"""
    for file in glob(f"{DirPath.output}/*/*.md"):
        with open(file, encoding="utf-8") as file_input:
            with open(out_file, "a", encoding="utf-8") as file_output:
                lines = (
                    re.sub(r"^#", r"##", x) if re.match(r"^#{0,6}+\s", x) else x
                    for x in file_input
                )
                file_output.writelines(lines)


def gen_md_blocklist(list_source, list_title):
    """Generate README.md for ABL from category README.md files."""
    file_badges = is_path(Path.joinpath(DirPath.base, "BADGES.md"))
    file_about = is_path(Path.joinpath(DirPath.base, "ABOUT.md"))
    file_notes = is_path(Path.joinpath(DirPath.base, "NOTE.md"))
    main_title = markdown_strings.header(ListInfo.title, 1)
    badges = read_file(file_badges, data_type="str")
    about = read_file(file_about, data_type="str")
    notes = read_file(file_notes, data_type="str")
    list_format = ["Domains", "ABP Filter"]
    info_add = markdown_strings.blockquote(
        "Generated Lists: "
        + ", ".join(list_title)
        + "\n\n"
        + "Formats: "
        + ", ".join(list_format)
        + "\n\n"
    )
    section = [
        main_title,
        info_add,
        badges if badges else None,
        about if about else None,
        "\n".join(md_blocklist_section_table(list_source)),
        notes if notes else None,
    ]
    data_md = "\n".join(filter(None, section)) + "\n\n"
    file_md_blocklist = is_path(Path.joinpath(DirPath.base, "README.md"))
    with open(file_md_blocklist, "w", encoding="utf-8") as file_output:
        file_output.writelines(data_md)
    concat_md_category(file_md_blocklist)


def main():
    """
    Main.
    """
    list_source = list(glob(f"{DirPath.input}/*.json"))
    list_title = []
    p_bar = ProgIter(list_source, desc=f"Generating lists")
    for i, file in enumerate(p_bar):
        blg = ListGenerator(file_json=file,)
        list_title.append(blg.data_json[blg.j_key.title])
        p_bar.set_description(desc=f"Processing sources — {blg.category}")
        blocked, unblocked, false_positives = process_sources(blg)
        if blocked:
            p_bar.set_description(
                desc=f"Removing duplicates & false positives — {blg.category}"
            )
            blocked, stats = remove_duplicates_false(blocked, false_positives)
            p_bar.set_description(
                desc=f"Removing redundant subdomains — {blg.category}"
            )
            blocked, main_domains, stats = remove_redundant(blocked, stats, blg)
            p_bar.set_description(desc=f"Finalising — {blg.category}")
            finalise(blg, blocked, unblocked, main_domains, stats)
        if i == len(list_source) - 1:
            p_bar.set_description(desc=f"Generating README.md for the {blg.info.title}")
            gen_md_blocklist(list_source, list_title)
            p_bar.set_description(desc="Done!")


if __name__ == "__main__":
    main()
