"""
aBL Generator

Creates compiled blocklists in ABP Filter List format.
Uses json files in a specific format containing list of well-known blocklists.
The source lists should be in Domains/Hosts or ABP Filter List format.
Duplicates and redundant subdomains are removed.
The generated lists are best used with DNS filtering tools which supports ABP style lists.
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
        domains_cname = set(
            ProgIter(
                pool.map(worker_get_cname, domains),
                total=len(domains),
                desc=f"Fetching CNAMEs",
                show_times=False,
                verbose=1,
            )
        )
    if None in domains_cname:
        domains_cname.remove(None)
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
        r"\ball\b"
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
        r"\ball\b"
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
    pattern_if_unblocked = re.compile(r"@@\|\|.+\^$|@@\|\|.+\^\$important$")
    unblocked = [
        x
        for x in content
        if re.match(pattern_if_unblocked, x, concurrent=True)
        and not re.match(pattern_unsupported, x, concurrent=True)
    ]
    unblocked_domains = [
        x.replace("@@||", "").replace("^", "").replace("$important", "")
        for x in unblocked
    ]
    unblocked = [x.replace("^", "^$important") for x in unblocked if x.endswith("^")]
    pattern_if_regexp = re.compile(r"^\/.*\/$", re.V1)
    regexp = [
        x
        for x in content
        if re.match(pattern_if_regexp, x, concurrent=True)
        and not re.match(pattern_unsupported, x, concurrent=True)
    ]
    return blocked, unblocked, unblocked_domains, regexp


def extract_hosts(content, is_false):
    """Extracts blocked or unblocked domains from hosts/domains style content."""
    pattern_list = [
        r"(?>\#|\!|\s+\#|\s+\!).*",
        r"^\s",
        r".*\blocalhost\b.*",
        r"^\d*\.\d*\.\d*\.\d*\s*(?>\s|www\.|m\.)",
        r"^(?>www\.|m\.)",
    ]
    pattern = re.compile("|".join(f"(?:{p})" for p in pattern_list), re.V1)
    domains = [re.sub(pattern, "", x, concurrent=True) for x in content]
    domains = [x for x in domains if valid_domain(x)]
    blocked, unblocked, unblocked_domains, regexp = [], [], [], []
    if is_false:
        unblocked_domains = domains
    else:
        blocked = domains
    return blocked, unblocked, unblocked_domains, regexp


def worker_process_sources(item, blg):
    """Worker for process_sources via ThreadPoolExecutor."""
    unprocessed = get_content(item[blg.i_key.url]).splitlines()
    if item[blg.i_key.abp_format]:
        blocked, unblocked, unblocked_domains, regexp = extract_abp(unprocessed)
    else:
        blocked, unblocked, unblocked_domains, regexp = extract_hosts(
            unprocessed, item[blg.i_key.unblock_list]
        )
    item[blg.i_key.last_modified] = get_last_modified(item[blg.i_key.url])
    item[blg.i_key.num_blocked] = len(blocked) + len(regexp)
    item[blg.i_key.num_unblocked] = len(unblocked_domains)
    # item[blg.i_key.num_regexp] = len(regexp)
    write_file(blg.data_json, blg.file_json)
    return blocked, unblocked, unblocked_domains, regexp


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
        blocked, unblocked, unblocked_domains, regexp = zip(
            *pool.map(
                worker_process_sources,
                blg.data_json[blg.j_key.sources],
                repeat(blg),
            )
        )

    blocked = chain.from_iterable(blocked)
    unblocked = chain.from_iterable(unblocked)
    unblocked_domains = chain.from_iterable(unblocked_domains)
    regexp = chain.from_iterable(regexp)
    return blocked, unblocked, unblocked_domains, regexp


def match_regex(domains, regex_list):
    """Match regex with domains."""
    regex_list = [x[1:-1] for x in regex_list]
    pattern = re.compile("|".join(regex_list))
    matches = [x for x in domains if re.match(pattern, x, concurrent=True)]
    return matches


def remove_duplicates_false(blg, blocked, unblocked_domains, regexp):
    """Removes duplicates and false positives from blocked domains."""
    stats = {}
    matched = match_regex(blocked, regexp)
    blocked = list(blocked)
    blocked = set(blocked) - set(matched)

    file_false_positives = is_path(
        Path.joinpath(DirPath.temp, f"false_positives_{blg.category}.txt")
    )
    unblocked_domains = set(unblocked_domains)
    unblocked_domains_cname = get_cname(unblocked_domains)
    unblocked_domains.update(unblocked_domains_cname)

    num_raw_blocked_domains = {"unprocessed": len(blocked)}
    stats.update(num_raw_blocked_domains)
    blocked = set(blocked) - set(unblocked_domains)
    if blg.category != "general":
        dir_general = Path.joinpath(DirPath.output, "general")
        file_general_false_positives = Path.joinpath(
            DirPath.temp, f"false_positives_general.txt"
        )
        file_general_domains = Path.joinpath(dir_general, OutputFile.abp_filter)
        if file_general_false_positives and file_general_domains:
            general_false_positives = {
                x.strip() for x in read_file(file_general_false_positives)
            }
            general_blocked_domains = {
                x.strip()
                for x in read_file(file_general_domains)
                if not str(x).startswith("!")
            }
            general_blocked_domains = {
                x.replace("||", "").replace("^", "") for x in general_blocked_domains
            }
            add_domains_to_remove = general_false_positives | general_blocked_domains
            blocked -= add_domains_to_remove
    num_blocked_domains = {
        "minus regex matches, duplicates, and false positives": len(blocked)
    }
    stats.update(num_blocked_domains)
    unblocked_domains = "\n".join(unblocked_domains)
    write_file(unblocked_domains, file_false_positives)
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


def remove_redundant(blg, blocked, unblocked, unblocked_domains, regexp, stats):
    """Removes sub-domains if main-domain is already in the list."""
    file_main_domains = is_path(
        Path.joinpath(DirPath.temp, f"main_domains_{blg.category}.txt")
    )
    cached_main_domains = {x.strip() for x in read_file(file_main_domains)}
    blocked = set(blocked)
    if cached_main_domains:
        identified_main_domains = blocked & cached_main_domains
        domains_to_check = blocked - identified_main_domains
    else:
        domains_to_check = blocked
        identified_main_domains = None
    with ProcessPoolExecutor() as pool:
        main_domains = set(
            ProgIter(
                pool.map(worker_return_main_domain, domains_to_check, chunksize=50),
                desc=f"Fetching main-domains — {blg.data_json[blg.j_key.title]}",
                total=len(domains_to_check),
                chunksize=50,
                verbose=1,
                show_times=False,
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
                desc=f"Extracting registered-domains from sub-domains — {blg.data_json[blg.j_key.title]}",
                total=len(sub_domains),
                chunksize=100,
                verbose=1,
                show_times=False,
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
                    desc=f"Matching redundant sub-domains — {blg.data_json[blg.j_key.title]}",
                    total=len(sub_domains),
                    verbose=1,
                    show_times=False,
                )
            )
        if None in unmatched_subdomains:
            unmatched_subdomains.remove(None)
        blocked = unmatched_subdomains | main_domains
        num_blocked_domains = {"minus redundant sub-domains": len(blocked)}
        stats.update(num_blocked_domains)
        write_file("\n".join(main_domains), file_main_domains)

    matched = match_regex(unblocked_domains, regexp)
    matched = [x.replace(x, f"@@||{x}^$important") for x in matched]
    unblocked = unblocked + matched
    return blocked, unblocked, main_domains, stats


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


def gen_lists(blg, blocked, unblocked, regexp):
    """Generates blocklist files in ABP format."""
    blocked = sorted(blocked)
    blocked = [x.replace(x, f"||{x}^") for x in blocked]
    unblocked = sorted(unblocked)
    regexp = sorted(regexp)
    list_title = f"{blg.info.title} - {blg.data_json[blg.j_key.title]}"
    header = (
        str(blg.info.header)
        .replace("repl_cat_title", list_title)
        .replace("repl_cat_desc", blg.data_json[blg.j_key.desc])
    )
    # file_domains = is_path(Path.joinpath(blg.dir_cat, OutputFile.domains))
    file_filter = is_path(Path.joinpath(blg.dir_cat, OutputFile.abp_filter))
    # blocked_domains = "\n".join(blocked)
    # with open(file_domains, "w", encoding="utf-8") as file:
    #     file.write(header.replace("repl_cmt", "#").replace("repl_alt_list", "ABP"))
    #     for line in blocked_domains:
    #         file.write(line)
    if blg.category != "general":
        file_general_list = Path.joinpath(DirPath.output, f"general/filter_list.txt")
        general_list = [x.strip() for x in read_file(file_general_list)]
        blocked_general = [x for x in general_list if x.startswith("||")]
        unblocked_general = [x for x in general_list if x.startswith("@@")]
        regexp_general = [x for x in general_list if x.startswith("/")]
        blocked = [x for x in blocked if x not in blocked_general]
        unblocked = [x for x in unblocked if x not in unblocked_general]
        regexp = [x for x in regexp if x not in regexp_general]

    blocked = "\n".join(blocked) + "\n"
    unblocked = "\n".join(unblocked) + "\n"
    regexp = "\n".join(regexp)
    with open(file_filter, "w", encoding="utf-8") as file:
        abp_pre_header = "[Adblock Plus 2.0]\n"
        file.write(abp_pre_header)
        file.write(header.replace("repl_cmt", "!").replace("alt_list", "domains"))
        if blocked:
            for line in blocked:
                file.write(line)
        if unblocked:
            for line in unblocked:
                file.write(line)
        if regexp:
            for line in regexp:
                file.write(line)
    gen_checksum(file_filter)


def category_section_main(blg, stats):
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
        f"""Rules before processing: {stats["unprocessed"]}""",
        f"""Rules after processing: {stats["minus redundant sub-domains"]}""",
    ]
    info_add = markdown_strings.unordered_list(info_list)
    string_bold = (
        f"aBL - {blg.data_json[blg.j_key.title]} is {value_percentage:.2f}% lighter"
    )
    sub_desc = (
        f"By using regex rules and by removing duplicates, false-positives and redundant sub-domains "
        f"the {markdown_strings.bold(string_bold)} than its combined sources"
    )
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
        5,
        column_lengths=[tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
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


def gen_category(blg, stats):
    """Generates README.md for the blocklist category."""
    section = [
        "\n\n".join(category_section_main(blg, stats)),
        "\n".join(category_section_table(blg)),
    ]
    data_md = "\n\n".join(section) + "\n\n"

    file_category = is_path(Path.joinpath(blg.dir_cat, "README.md"))
    write_file(data_md, file_category)


def gen_potential(blg, blocked, false_positives, num=10):
    """Generates a list of frequently blocked main domains."""
    file_potential = is_path(
        Path.joinpath(DirPath.temp, f"potential_{blg.category}.txt")
    )
    cached_potential = {x.strip() for x in read_file(file_potential)}
    domains_to_check = blocked - cached_potential if cached_potential else blocked
    with ProcessPoolExecutor() as pool:
        main_domains = list(
            ProgIter(
                pool.map(
                    worker_extract_registered_domain, domains_to_check, chunksize=100
                ),
                desc=f"Identifying potential domains — {blg.data_json[blg.j_key.title]}",
                total=len(domains_to_check),
                chunksize=100,
                verbose=1,
                show_times=False,
            )
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


def finalise(blg, blocked, unblocked, regexp, false_positives, stats):
    """Finalises the lists by,
    generating blocklists,
    generating README.md for the blocklist category,
    generating a list of potential domains to be blocked and,
    generating a file with version info.
    """
    gen_lists(blg, blocked, unblocked, regexp)
    gen_category(blg, stats)
    if datetime.now().strftime("%A") == "Saturday":
        gen_potential(blg, blocked, false_positives)
    write_version(blg)


def blocklist_section_table(list_sources):
    """The table for the blocklist README.md file."""
    tbl_col_tup = namedtuple("tbl_col_tup", "c1, c2, c3, c4")
    tbl_col_arr = ["#", "TITLE", "DESCRIPTION", "ABP FILTER LIST"]
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
            "Link",
            f"{blg.info.repo}/raw/master/lists/{blg.category}/{OutputFile.abp_filter}",
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
            "Link",
            f"{blg.info.repo}/raw/master/lists/{blg.category}/{OutputFile.abp_filter}",
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
    files = glob(f"{DirPath.output}/*/*.md")
    files = sorted(files, key=lambda x: x)
    files = sorted(files, key=lambda x: x.__contains__("regional"))
    for file in files:
        with open(file, encoding="utf-8") as file_input:
            with open(out_file, "a", encoding="utf-8") as file_output:
                lines = (
                    re.sub(r"^#", r"##", x) if re.match(r"^#{0,6}+\s", x) else x
                    for x in file_input
                )
                file_output.writelines(lines)


def gen_blocklist(list_source, list_title):
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
        badges if badges else None,
        info_add,
        "\n".join(blocklist_section_table(list_source)),
        about if about else None,
        notes if notes else None,
    ]
    data_md = "\n\n".join(filter(None, section)) + "\n\n"
    file_blocklist = is_path(Path.joinpath(DirPath.base, "README.md"))
    with open(file_blocklist, "w", encoding="utf-8") as file_output:
        file_output.writelines(data_md)
    concat_category(file_blocklist)


@dataclass
class DirPath:
    """For the source json file."""

    base = Path(__file__).parents[0]
    input = is_path(Path.joinpath(base, "sources"))
    output = is_path(Path.joinpath(base, "lists"))
    temp = is_path(Path.joinpath(base, ".temp"))


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

    title = "arapurayil's Block List (aBL)"
    author = "arapurayil"
    version = (
        str(int(datetime.now().strftime("%Y")) - 2019)
        + "."
        + datetime.now().strftime("%m")
        + "."
        + datetime.now().strftime("%d")
    )
    last_modified = datetime.now().strftime("%d %b %Y %H:%M:%S IST")
    expires = "1 day"
    repo = "https://github.com/arapurayil/aBL"

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@dataclass
class OutputFile:
    """Output file names."""

    # unblocked_domains = "internal_use_only.txt"
    # domains = "blocked_domains.txt"
    abp_filter = "filter_list.txt"


@dataclass
class ListGenerator:
    """The main class."""

    j_key = JsonKey(
        title="title",
        desc="description",
        sources="sources",
    )
    i_key = ItemKey(
        title="title",
        url="url",
        desc="description",
        abp_format="abp_format",
        unblock_list="unblock_list",
        num_blocked="num_blocked",
        num_unblocked="num_unblocked",
        num_regexp="num_regexp",
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
            # f"repl_cmt You can find lists for other categories in the repo\n"
            # f"repl_cmt This list is also available in repl_alt_list format\n"
            f"repl_cmt\n"
            f"repl_cmt Issues: {ListInfo.repo}/issues\n"
            f"repl_cmt Please report the domains you wish to block/unblock via 'Issues'\n"
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


def main():
    """
    Main.
    """
    list_source = list(glob(f"{DirPath.input}/*.json"))
    # list_source = sorted(list_source, key=lambda x: x)
    list_source = sorted(list_source, key=lambda x: x.__contains__("regional"))
    list_source = sorted(
        list_source, key=lambda x: x.__contains__("general"), reverse=True
    )
    p_bar = ProgIter(list_source, desc=f"Generating lists", verbose=1, show_times=False)
    if list_source:
        list_title = []
        for i, file in enumerate(p_bar):
            blg = ListGenerator(
                file_json=file,
            )
            list_title.append(blg.data_json[blg.j_key.title])
            p_bar.set_description(
                desc=f"Processing sources — {blg.data_json[blg.j_key.title]}"
            )
            blocked, unblocked, unblocked_domains, regexp = process_sources(blg)
            blocked = list(blocked)
            unblocked = list(unblocked)
            unblocked_domains = list(unblocked_domains)
            regexp = list(regexp)
            if blocked:
                p_bar.set_description(
                    desc=f"Removing regex matches, duplicates & false positives — {blg.data_json[blg.j_key.title]}"
                )

                blocked, stats = remove_duplicates_false(
                    blg, blocked, unblocked_domains, regexp
                )
                p_bar.set_description(
                    desc=f"Removing redundant subdomains — {blg.data_json[blg.j_key.title]}"
                )
                blocked, unblocked, main_domains, stats = remove_redundant(
                    blg, blocked, unblocked, unblocked_domains, regexp, stats
                )
                p_bar.set_description(
                    desc=f"Finalising — {blg.data_json[blg.j_key.title]}"
                )
                finalise(blg, blocked, unblocked, regexp, main_domains, stats)
            if i == len(list_source) - 1:
                p_bar.set_description(
                    desc=f"Generating README.md for the {blg.info.title}"
                )
                gen_blocklist(list_source, list_title)
                p_bar.set_description(desc="Done!")
    else:
        print("No sources to process!\nAdd json files to 'sources' directory.")


if __name__ == "__main__":
    main()
