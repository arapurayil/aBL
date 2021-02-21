"""
aBL - Generator
"""
from base64 import b64encode
from collections import namedtuple, Counter
from concurrent.futures.process import ProcessPoolExecutor
from concurrent.futures.thread import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from glob import glob
from hashlib import md5
from itertools import repeat, chain
from json import load, loads, dump
from pathlib import Path
from textwrap import fill

# from PyFunceble import DomainAndIPAvailabilityChecker as DomainStatus


from dns import resolver, exception as dns_exception
from regex import regex as re
from requests import Session
from requests.adapters import HTTPAdapter, Retry
from tldextract import TLDExtract as TLDex
from tqdm import tqdm
from validators import domain as valid_domain

import markdown_strings


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


@dataclass
class DirPath:
    """For the source json file."""

    base = Path(__file__).parents[0]
    input = is_path(Path.joinpath(base, "sources"))
    core = is_path(Path.joinpath(base, "core"))
    output_filters = is_path(Path.joinpath(base, "filters"))
    temp = is_path(Path.joinpath(base, ".temp"))


@dataclass
class JsonKey:
    """Keys for the source json file."""

    def __init__(self, **kwargs):
        self.desc = None
        self.title = None
        self.__dict__.update(kwargs)


@dataclass
class ItemKey:
    """Keys for the individual source items in the source json file"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@dataclass
class ListInfo:
    """Values for the list header."""

    title = "aBL"
    author = "arapurayil"
    version = (
        str(int(datetime.now().strftime("%Y")) - 2019)
        + "."
        + datetime.now().strftime("%m")
        + "."
        + datetime.now().strftime("%d")
    )
    last_modified = datetime.now().strftime("%d %b %Y %H:%M:%S UTC")
    expires = "12 hours"
    repo = "https://github.com/arapurayil/aBL"
    home = "https://abl.arapurayil.com"

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@dataclass
class ListGenerator:
    """The main class."""

    j_key = JsonKey(
        title="title",
        desc="description",
        sources="sources",
    )
    i_key = ItemKey(
        name="name",
        url="url",
        desc="desc",
        format="format",
        type="type",
        num_block_rules="num_block_rules",
        num_unblock_rules="num_unblock_rules",
    )
    info = ListInfo(
        header=(
            f"repl_cmt Title: repl_cat_title\n"
            f"repl_cmt Author: {ListInfo.author}\n"
            f"repl_cmt Description: repl_cat_desc\n"
            f"repl_cmt Version: {ListInfo.version}\n"
            f"repl_cmt Last modified: {ListInfo.last_modified}\n"
            f"repl_cmt Expires: {ListInfo.expires} (update frequency)\n"
            f"repl_cmt Home: {ListInfo.home}\n"
            f"repl_cmt Repository: {ListInfo.repo}\n"
            f"repl_cmt Issues: {ListInfo.repo}/issues\n"
            f"repl_cmt Please report the domains you wish to block/unblock via 'Issues'\n"
            f"repl_cmt Licence: {ListInfo.repo}/license\n"
            f"repl_cmt-----------------------------------------"
            f"---------------------------------------------repl_cmt\n"
        ),
    )

    def __init__(self, file_json, **kwargs):
        self.file_json = file_json
        self.category = Path(file_json).stem
        self.data_json = read_file(file_json)
        self.dir_output_filters = DirPath.output_filters
        self.dir_cat = Path.joinpath(DirPath.input, Path(file_json).stem)
        self.__dict__.update(kwargs)


def extract_abp(content):
    """Extracts blocked and unblocked domains from ABP style content."""
    pattern_unsupported = re.compile(r"\S+(?>\/|\=)\S+", re.V1)
    pattern_supported_block = re.compile(
        r"^\|\|.+\^(?>$|.+(?:"
        r"\bfirst-party\b|"
        r"\b1p\b|"
        r"\bthird-party\b|"
        r"\b3p\b|"
        r"\bdocument\b|"
        r"\ball\b"
        # r"\ball\b|"
        # r"\bpopup\b"
        r"))",
        re.V1,
    )
    pattern_scrub_blocked_list = [
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
    pattern_scrub_blocked = re.compile(
        "|".join(f"(?:{p})" for p in pattern_scrub_blocked_list), re.V1
    )
    block_rules = [
        x
        for x in content
        if re.match(pattern_supported_block, x, concurrent=True)
        and not re.match(pattern_unsupported, x, concurrent=True)
    ]

    blocked_domains = [
        re.sub(pattern_scrub_blocked, "", x, concurrent=True) for x in block_rules
    ]
    blocked_domains = [x for x in blocked_domains if valid_domain(x)]
    pattern_supported_unblock = re.compile(r"@@\|\|.+\^$")
    unblock_rules = [
        x
        for x in content
        if re.match(pattern_supported_unblock, x, concurrent=True)
        and not re.match(pattern_unsupported, x, concurrent=True)
    ]
    unblocked_domains = [
        x.replace("@@||", "").replace("^", "").replace("$important", "")
        for x in unblock_rules
    ]
    regex_rules = []
    return blocked_domains, unblocked_domains, unblock_rules, regex_rules


def extract_regex(content):
    """
    Extracts regex rules within two '/'.
    """
    pattern_if_regexp = re.compile(r"^\/.*\/$", re.V1)
    regex_rules = [
        x for x in content if re.match(pattern_if_regexp, x, concurrent=True)
    ]
    return regex_rules


def extract_hosts(content, list_type):
    """Extracts blocked or unblocked domains from hosts/domains style content."""
    pattern_scrub = [
        r"(?>\#|\!|\s+\#|\s+\!).*",
        r"^\s",
        r".*\blocalhost\b.*",
        r"^\d*\.\d*\.\d*\.\d*\s*(?>\s|www\.|m\.)",
        r"^(?>www\.|m\.)",
    ]
    pattern = re.compile("|".join(f"(?:{p})" for p in pattern_scrub), re.V1)
    domains = [re.sub(pattern, "", x, concurrent=True) for x in content]
    domains = [x for x in domains if valid_domain(x)]
    blocked_domains, unblocked_domains, cname_list = [], [], []
    if list_type == "unblock":
        unblocked_domains = domains
    if list_type == "block":
        blocked_domains = domains
    if list_type == "cname":
        cname_list = domains
    return blocked_domains, unblocked_domains, cname_list


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


def worker_process_sources(item, blg):
    """Worker for process_sources via ThreadPoolExecutor."""
    unprocessed = get_content(item[blg.i_key.url]).splitlines()
    blocked_domains, unblocked_domains, unblock_rules, regex_rules, cname_list = (
        [],
        [],
        [],
        [],
        [],
    )
    if item[blg.i_key.type] == "regex":
        regex_rules = extract_regex(unprocessed)
    else:
        if item[blg.i_key.format] == "abp":
            (
                blocked_domains,
                unblocked_domains,
                unblock_rules,
                regex_rules,
            ) = extract_abp(unprocessed)
        if item[blg.i_key.format] == "domains":
            blocked_domains, unblocked_domains, cname_list = extract_hosts(
                unprocessed, item[blg.i_key.type]
            )

    item[blg.i_key.num_block_rules] = (
        len(blocked_domains) + len(regex_rules) + len(cname_list)
    )
    item[blg.i_key.num_unblock_rules] = len(unblocked_domains)
    write_file(blg.data_json, blg.file_json)
    return blocked_domains, unblocked_domains, unblock_rules, regex_rules, cname_list


def remove_common_sub(domains):
    """
    Remove www. and m. subdomains
    """
    pattern = re.compile(r"^(?>www\.|m\.)")
    domains = [re.sub(pattern, "", x, concurrent=True) for x in domains]
    return set(domains)


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
    """Worker for get_cname."""
    try:
        answer = dns_resolver().resolve(item, "CNAME")
        for cname_val in answer:
            return str(cname_val.target).rstrip(".")
    except (
        resolver.NoAnswer,
        resolver.NXDOMAIN,
        dns_exception.Timeout,
        resolver.NoNameservers,
    ):
        pass


def get_cname(domains):
    """Fetches CNAME of a list of domains."""
    with ThreadPoolExecutor(max_workers=100) as pool:
        domains_cname = list(
            tqdm(
                pool.map(worker_get_cname, domains, chunksize=100),
                total=len(domains),
                desc=f"Fetching CNAMEs",
                leave=False,
            )
        )

    domains_cname = set(domains_cname)
    if None in domains_cname:
        domains_cname.remove(None)
    return domains_cname


def remove_unblocked_from_blocked(blocked_domains, unblocked_domains):
    """
    Remove excluded domains from blocked domains

    """
    # unblocked_domains |= remove_common_sub(unblocked_domains)
    # cnames are included in the unblock list
    # unblocked_domains |= get_cname(unblocked_domains)
    blocked_domains -= unblocked_domains

    return blocked_domains, unblocked_domains


def process_sources(blg):
    """Processes the source json file for the category
    Fetches the content for the url for each individual source and,
    extracts blocked and unblocked domains from it and,
    appends it the unified blocked and unblocked domains for the category.
    """
    blg.data_json[blg.j_key.sources] = sorted(
        blg.data_json[blg.j_key.sources], key=lambda x: x[blg.i_key.name].upper()
    )
    with ProcessPoolExecutor() as pool:
        (
            blocked_domains,
            unblocked_domains,
            unblock_rules,
            regex_rules,
            cname_list,
        ) = zip(
            *pool.map(
                worker_process_sources,
                blg.data_json[blg.j_key.sources],
                repeat(blg),
                chunksize=10,
            )
        )

    blocked_domains = chain.from_iterable(blocked_domains)
    unblocked_domains = chain.from_iterable(unblocked_domains)
    unblock_rules = chain.from_iterable(unblock_rules)
    regex_rules = chain.from_iterable(regex_rules)
    cname_list = chain.from_iterable(cname_list)

    return blocked_domains, unblocked_domains, unblock_rules, regex_rules, cname_list


def worker_get_not_active(item):
    """
    Worker for get_not_active
    """
    # time consuming
    # if not DomainStatus(item).get_status().is_active():
    #     return item
    try:
        dns_resolver().resolve(item)
    except (
        resolver.NoAnswer,
        resolver.NXDOMAIN,
        resolver.NoNameservers,
    ):
        return item
    except dns_exception.Timeout:
        pass


def get_not_active(domains):
    """
    Gets non active domains.
    """
    with ThreadPoolExecutor(max_workers=100) as pool:
        not_active = list(
            tqdm(
                pool.map(worker_get_not_active, domains, chunksize=100),
                total=len(domains),
                leave=False,
            )
        )
    return not_active


def only_active(domains):
    """
    Removes non-active domains from list of domains
    """
    not_active_domains = get_not_active(domains)
    active_domains = domains - set(not_active_domains)
    return active_domains, not_active_domains


def extract_tld(domain):
    """Defines tldextract to include psl private domains."""
    extract = TLDex(include_psl_private_domains=True)
    return extract(domain)


def worker_return_main_domain(domain):
    """Worker for remove_redundant
    to get main domains.
    """
    if not extract_tld(domain).subdomain:
        return domain
    return None


def worker_extract_registered_domain(domain):
    """Worker for remove_redundant
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


def compress_rules(blg, all_domains):
    """
    Removes redundant subdomain rules
    """
    file_main_domains = is_path(
        Path.joinpath(DirPath.temp, f"main_domains_{blg.category}.txt")
    )
    cached_main_domains = {x.strip() for x in read_file(file_main_domains)}
    if cached_main_domains:
        identified_main_domains = all_domains & cached_main_domains
        domains_to_check = all_domains - identified_main_domains
    else:
        domains_to_check = all_domains
        identified_main_domains = None

    with ProcessPoolExecutor() as pool:
        main_domains = list(
            tqdm(
                pool.map(worker_return_main_domain, domains_to_check, chunksize=100),
                desc=f"Fetching main-domains — {blg.data_json[blg.j_key.title]}",
                total=len(domains_to_check),
                leave=False,
            )
        )
    main_domains = set(main_domains)
    if identified_main_domains:
        main_domains = main_domains | identified_main_domains

    if None in main_domains:
        main_domains.remove(None)
    sub_domains = all_domains - main_domains
    with ProcessPoolExecutor() as pool:
        sub_main_domains = list(
            tqdm(
                pool.map(worker_extract_registered_domain, sub_domains, chunksize=100),
                desc=f"Extracting registered-domains from sub-domains — {blg.data_json[blg.j_key.title]}",
                total=len(sub_domains),
                leave=False,
            )
        )
    file_potential = is_path(
        Path.joinpath(DirPath.temp, f"potential_{blg.category}.txt")
    )
    potential = [x for x in sub_main_domains]
    potential = Counter(potential).most_common()
    num = 10
    potential = {k for k, v in potential if v > num}
    potential = "\n".join(filter(None, potential))
    write_file(potential, file_potential)

    sub_main_domains = set(sub_main_domains)
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
        with ProcessPoolExecutor() as pool:
            unmatched_subdomains = list(
                tqdm(
                    pool.map(
                        worker_unmatched_item,
                        sub_domains,
                        repeat(pattern),
                        chunksize=100,
                    ),
                    desc=f"Matching redundant sub-domains — {blg.data_json[blg.j_key.title]}",
                    total=len(sub_domains),
                    leave=False,
                )
            )
        unmatched_subdomains = set(unmatched_subdomains)
        if None in unmatched_subdomains:
            unmatched_subdomains.remove(None)
        all_domains = unmatched_subdomains | main_domains
        write_file("\n".join(main_domains), file_main_domains)

    return all_domains


def match_regex(domains, regex_rules):
    """
    Match domains against regex
    """
    regex_list = [x[1:-1] for x in regex_rules]
    pattern = re.compile("|".join(regex_list))
    matches = [x for x in domains if re.findall(pattern, x, concurrent=True)]
    return matches


def regex_redundant(blocked_domains, unblocked_domains, unblock_rules, regex_rules):
    """
    Remove domain rules already blocked by regex
    """
    matched_blocked_domains = match_regex(blocked_domains, regex_rules)
    blocked_domains -= set(matched_blocked_domains)
    matched_unblocked_domains = match_regex(unblocked_domains, regex_rules)
    matched_unblocked_rules = [
        x.replace(x, f"@@||{x}^") for x in matched_unblocked_domains
    ]
    # unblock_rules |= set(matched_unblocked_rules)
    # unblock rules from source list is avoided
    unblock_rules = set(matched_unblocked_rules)

    return blocked_domains, unblock_rules


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


def write_version(blg):
    """Writes version number to a file."""
    file_version = Path.joinpath(DirPath.base, "version.txt")
    write_file(blg.info.version, file_version)


def gen_filter_list(blg, blocked_domains, unblock_rules, regex_rules):
    """
    Generate filter list
    """
    file_filter = is_path(Path.joinpath(blg.dir_output_filters, f"{blg.category}.txt"))
    blocked_domains = sorted(blocked_domains)
    block_rules = [x.replace(x, f"||{x}^") for x in blocked_domains]
    unblock_rules = sorted(unblock_rules)
    regex_rules = sorted(regex_rules) if regex_rules else ""
    list_title = f"{blg.info.title} - {blg.data_json[blg.j_key.title]}"
    header = (
        str(blg.info.header)
        .replace("repl_cat_title", list_title)
        .replace("repl_cat_desc", blg.data_json[blg.j_key.desc])
    )
    override_rules = []
    if blg.category != "main":
        file_general_list = Path.joinpath(DirPath.output_filters, f"main.txt")
        file_override_list = Path.joinpath(DirPath.core, f"{blg.category}_override.txt")
        general_list = [x.strip() for x in read_file(file_general_list)]
        override_rules = [x.strip() for x in read_file(file_override_list)]
        block_rules_main = [x for x in general_list if x.startswith("||")]
        unblock_rules_main = [x for x in general_list if x.startswith("@@")]
        regex_rules_main = [x for x in general_list if x.startswith("/")]
        block_rules = [x for x in block_rules if x not in block_rules_main]
        unblock_rules = [x for x in unblock_rules if x not in unblock_rules_main]
        regex_rules = [x for x in regex_rules if x not in regex_rules_main]

    _num_processed = 0
    _num_processed += len(block_rules)
    _num_processed += len(unblock_rules)
    _num_processed += len(regex_rules)
    _num_processed += len(override_rules)

    block_rules = "\n".join(block_rules) + "\n"
    unblock_rules = "\n".join(unblock_rules) + "\n"
    regex_rules = "\n".join(regex_rules) + "\n"
    override_rules = "\n".join(override_rules) + "\n"

    with open(file_filter, "w", encoding="utf-8") as file:
        abp_pre_header = "[Adblock Plus 2.0]\n"
        file.write(abp_pre_header)
        file.write(header.replace("repl_cmt", "!").replace("alt_list", "domains"))
        if block_rules:
            for line in block_rules:
                file.write(line)
        if unblock_rules:
            for line in unblock_rules:
                file.write(line)
        if regex_rules:
            for line in regex_rules:
                file.write(line)
        if override_rules:
            for line in override_rules:
                file.write(line)

    gen_checksum(file_filter)
    write_version(blg)
    return _num_processed


def category_section_main(blg, stats):
    """Generates the main section of the category README.md file."""
    value_percentage = float(
        (
            (int(stats["unprocessed"]) - int(stats["processed"]))
            / int(stats["unprocessed"])
        )
        * 100
    )
    link_filter = markdown_strings.link(
        "Download",
        f"{blg.info.home}/filters/{blg.category}.txt",
    )
    main_title = (
        markdown_strings.header(f"{blg.data_json[blg.j_key.title]}", 1)
        + "\n"
        + "**"
        + link_filter
        + "**"
    )

    main_desc = markdown_strings.bold(f"{fill(blg.data_json[blg.j_key.desc])}")
    info_list = [
        f"Sources: {len(blg.data_json[blg.j_key.sources])}",
        f"""Rules before processing: {stats["unprocessed"]}""",
        f"""Rules after processing: {stats["processed"]}""",
    ]
    info_add = markdown_strings.unordered_list(info_list)
    string_bold = (
        f"aBL - {blg.data_json[blg.j_key.title]} is {value_percentage:.2f}% lighter"
    )
    sub_desc = f"The {markdown_strings.bold(string_bold)} than its combined sources"
    return [main_title, main_desc, info_add, sub_desc]


def category_section_table(blg):
    """Generates the table for the category README.md file."""
    tbl_col_tup = namedtuple("tbl_col_tup", "c1, c2, c3, c4, c5")
    tbl_col_arr = [
        "#",
        "Title",
        "Description",
        "Blocking rules",
        "Unblocking rules",
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
        if len(str(f"[{key[blg.i_key.name]}]({key[blg.i_key.url]})")) > tbl_pad.c2:
            tbl_pad_arr[1] = (
                len(str(f"[{key[blg.i_key.name]}]({key[blg.i_key.url]})")) + 2
            )
        if len(str({key[blg.i_key.desc]})) > tbl_pad.c3:
            tbl_pad_arr[2] = len(str({key[blg.i_key.desc]})) + 2
        if len(str({key[blg.i_key.num_block_rules]})) > tbl_pad.c4:
            tbl_pad_arr[3] = len(str({key[blg.i_key.num_block_rules]})) + 2
        if len(str({key[blg.i_key.num_unblock_rules]})) > tbl_pad.c5:
            tbl_pad_arr[4] = len(str({key[blg.i_key.num_unblock_rules]})) + 2
        tbl_pad = tbl_col_tup(*tbl_pad_arr)
    table_title_row = markdown_strings.table_row(
        [tbl_col.c1, tbl_col.c2, tbl_col.c3, tbl_col.c4, tbl_col.c5],
        [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
    )
    table_delimiter = markdown_strings.table_delimiter_row(
        5,
        column_lengths=[tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
    )
    table_contents = []
    for index, key in enumerate(blg.data_json[blg.j_key.sources]):
        link = markdown_strings.link(key[blg.i_key.name], key[blg.i_key.url])
        row = markdown_strings.table_row(
            [
                str(index + 1).zfill(2),
                link,
                key[blg.i_key.desc],
                key[blg.i_key.num_block_rules],
                key[blg.i_key.num_unblock_rules],
            ],
            [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
        )
        table_contents.append(row)
    return [table_title_row, table_delimiter, "\n".join(table_contents)]


def gen_category(blg, stats):
    """Generates README.md for the blocklist category."""
    section = [
        "\n\n".join(category_section_main(blg, stats)),
        "\n".join(category_section_table(blg)),
    ]
    data_md = "\n\n".join(section) + "\n\n"

    file_category = is_path(Path.joinpath(blg.dir_cat, "README.md"))
    write_file(data_md, file_category)


def blocklist_section_table(list_sources):
    """The table for the blocklist README.md file."""
    tbl_col_tup = namedtuple("tbl_col_tup", "c1, c2, c3, c4")
    tbl_col_arr = ["#", "TITLE", "DESCRIPTION", "DOWNLOAD LINK"]
    tbl_col = tbl_col_tup(*tbl_col_arr)
    tbl_pad_arr = [
        len("---"),
        len(tbl_col.c2),
        len(tbl_col.c3),
        len(tbl_col.c4),
    ]
    table_contents = []
    tbl_pad = tbl_col_tup(*tbl_pad_arr)
    for index, file in enumerate(list_sources):
        blg = ListGenerator(
            file_json=file,
        )
        filter_list_link = markdown_strings.link(
            f"{blg.info.home}/filters/{blg.category}.txt",
            f"{blg.info.home}/filters/{blg.category}.txt",
        )
        if len(str(index + 1).zfill(2)) > tbl_pad.c1:
            tbl_pad_arr[0] = len(str(index + 1).zfill(2)) + 2
        if len(str(blg.data_json[blg.j_key.title])) > tbl_pad.c2:
            tbl_pad_arr[1] = len(str(blg.data_json[blg.j_key.title])) + 2
        if len(str(blg.data_json[blg.j_key.desc])) > tbl_pad.c3:
            tbl_pad_arr[2] = len(str(blg.data_json[blg.j_key.desc])) + 2
        if len(str(filter_list_link)) > tbl_pad.c4:
            tbl_pad_arr[3] = len(str(filter_list_link)) + 2
        tbl_pad = tbl_col_tup(*tbl_pad_arr)
    for index, file in enumerate(list_sources):
        blg = ListGenerator(
            file_json=file,
        )
        filter_list_link = markdown_strings.link(
            f"{blg.info.home}/filters/{blg.category}.txt",
            f"{blg.info.home}/filters/{blg.category}.txt",
        )
        row = markdown_strings.table_row(
            [
                str(index + 1).zfill(2),
                str(blg.data_json[blg.j_key.title]),
                str(blg.data_json[blg.j_key.desc]),
                str(filter_list_link),
            ],
            [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4],
        )
        table_contents.append(row)
    table_delimiter = markdown_strings.table_delimiter_row(
        4, column_lengths=[tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4]
    )
    table_title_row = markdown_strings.table_row(
        [tbl_col.c1, tbl_col.c2, tbl_col.c3, tbl_col.c4],
        [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4],
    )
    return [table_title_row, table_delimiter, "\n".join(table_contents)]


def concat_category(out_file):
    """Concatenate category README.md files"""
    files = glob(f"{DirPath.input}/*/*.md")
    files = sorted(files, key=lambda x: x)
    files = sorted(files, key=lambda x: x.__contains__("regional"))
    files = sorted(files, key=lambda x: x.__contains__("main"), reverse=True)
    for file in files:
        with open(file, encoding="utf-8") as file_input:
            with open(out_file, "a", encoding="utf-8") as file_output:
                lines = (
                    re.sub(r"^#", r"##", x) if re.match(r"^#{0,6}+\s", x) else x
                    for x in file_input
                )
                file_output.writelines(lines)


def gen_project_readme(list_source, list_title):
    """Generate README.md for aBL from category README.md files."""
    file_badges = is_path(Path.joinpath(DirPath.base, "BADGES.md"))
    file_about = is_path(Path.joinpath(DirPath.base, "ABOUT.md"))
    file_notes = is_path(Path.joinpath(DirPath.base, "NOTE.md"))
    main_title = markdown_strings.header(ListInfo.title, 1)
    badges = read_file(file_badges, data_type="str")
    about = read_file(file_about, data_type="str")
    notes = read_file(file_notes, data_type="str")
    # list_format = ["Domains", "ABP Filter"]
    # info_add = markdown_strings.blockquote(
    #     "Generated Lists: "
    #     + ", ".join(list_title)
    #     # + "\n\n"
    #     # + "Formats: "
    #     # + ", ".join(list_format)
    # )
    info_add = markdown_strings.blockquote(
        "a filter list optimized for DNS level blocking of ads, "
        "analytics, crypto-jacking and other such threats/nuisances."
    )
    section = [
        main_title,
        info_add,
        badges if badges else None,
        about if about else None,
        "\n".join(blocklist_section_table(list_source)),
        notes if notes else None,
    ]
    data_md = "\n\n".join(filter(None, section)) + "\n\n"
    file_readme = is_path(Path.joinpath(DirPath.base, "README.md"))
    with open(file_readme, "w", encoding="utf-8") as file_output:
        file_output.writelines(data_md)
    concat_category(file_readme)


def main():
    """
    Main
    """
    list_source = list(glob(f"{DirPath.input}/*.json"))
    list_source = sorted(list_source, key=lambda x: x)
    list_source = sorted(
        list_source, key=lambda x: x.__contains__("main"), reverse=True
    )
    list_title = []
    if list_source:
        p_bar = tqdm(list_source, desc=f"Generating lists")
        for i, file in enumerate(p_bar):
            lg = ListGenerator(
                file_json=file,
            )
            list_title.append(lg.data_json[lg.j_key.title])
            p_bar.set_description(
                desc=f"Processing sources — {lg.data_json[lg.j_key.title]}"
            )
            (
                blocked_domains,
                unblocked_domains,
                unblock_rules,
                regex_rules,
                cname_list,
            ) = process_sources(lg)

            stats = {}
            blocked_domains = list(blocked_domains)
            unblocked_domains = list(unblocked_domains)
            unblock_rules = list(unblock_rules)
            regex_rules = list(regex_rules)
            cname_list = list(cname_list)
            num_unprocessed = {
                "unprocessed": len(blocked_domains)
                + len(unblock_rules)
                + len(regex_rules)
                + len(cname_list)
            }
            stats.update(num_unprocessed)

            blocked_domains = set(blocked_domains)
            unblocked_domains = set(unblocked_domains)
            unblock_rules = set(unblock_rules)
            regex_rules = set(regex_rules)
            cname_list = set(cname_list)
            p_bar.set_description(
                desc=f"Applying exclusions — {lg.data_json[lg.j_key.title]}"
            )
            blocked_domains, unblocked_domains = remove_unblocked_from_blocked(
                blocked_domains, unblocked_domains
            )
            blocked_domains = set(blocked_domains)
            unblocked_domains = set(unblocked_domains)
            p_bar.set_description(
                desc=f"Removing non-active domains — {lg.data_json[lg.j_key.title]}"
            )
            blocked_domains, not_active_blocked_domains = only_active(blocked_domains)
            p_bar.set_description(
                desc=f"Compressing rules — {lg.data_json[lg.j_key.title]}"
            )
            blocked_domains |= cname_list
            blocked_domains = compress_rules(lg, blocked_domains)
            blocked_domains, unblock_rules = regex_redundant(
                blocked_domains, unblocked_domains, unblock_rules, regex_rules
            )
            _num_processed = gen_filter_list(
                lg, blocked_domains, unblock_rules, regex_rules
            )
            num_processed = {"processed": _num_processed}
            stats.update(num_processed)
            gen_category(lg, stats)

            if i == len(list_source) - 1:
                p_bar.set_description(
                    desc=f"Generating README.md for the {lg.info.title}"
                )
                gen_project_readme(list_source, list_title)
                p_bar.set_description(desc="Done!")
    else:
        print("No sources to process!\nAdd json files to 'sources' directory.")


if __name__ == "__main__":
    main()
