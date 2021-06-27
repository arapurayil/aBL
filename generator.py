import subprocess
from base64 import b64encode
from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime
from glob import glob
from hashlib import md5
from itertools import chain
from json import load, loads, dump
from pathlib import Path
from textwrap import fill

from regex import regex as re
from requests import Session
from requests.adapters import HTTPAdapter, Retry
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
    hc_config = is_path(Path.joinpath(base, "config"))
    output_filters = is_path(Path.joinpath(base, "filters"))


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


def extract_regex(content):
    """
    Extracts regex rules within two '/'.
    """
    pattern_if_regexp = re.compile(r"^\/.*\/$", re.V1)
    return [x for x in content if re.match(pattern_if_regexp, x, concurrent=True)]


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
    blocked_domains, unblocked_domains = [], []
    if list_type == "unblock":
        unblocked_domains = domains
    if list_type == "block":
        blocked_domains = domains

    return blocked_domains, unblocked_domains


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
    blocked_domains, unblocked_domains, unblock_rules, regex_rules = (
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
            blocked_domains, unblocked_domains = extract_hosts(
                unprocessed, item[blg.i_key.type]
            )

    item[blg.i_key.num_block_rules] = len(blocked_domains) + len(regex_rules)
    item[blg.i_key.num_unblock_rules] = len(unblocked_domains)
    write_file(blg.data_json, blg.file_json)
    return blocked_domains, unblocked_domains, unblock_rules, regex_rules


def process_sources(blg):
    """Processes the source json file for the category
    Fetches the content for the url for each individual source and,
    extracts blocked and unblocked domains from it and,
    appends it the unified blocked and unblocked domains for the category.
    """
    blg.data_json[blg.j_key.sources] = sorted(
        blg.data_json[blg.j_key.sources], key=lambda x: x[blg.i_key.name].upper()
    )
    blocked_domains, unblocked_domains, unblock_rules, regex_rules = (
        [],
        [],
        [],
        [],
    )

    blocked_d, unblocked_d, unblock_r, regex_r = [], [], [], []
    for item in blg.data_json[blg.j_key.sources]:
        unprocessed = get_content(item[blg.i_key.url]).splitlines()
        if item[blg.i_key.type] == "regex":
            regex_r = extract_regex(unprocessed)
            regex_rules.append(regex_r)
        else:
            if item[blg.i_key.format] == "abp":
                (
                    blocked_d,
                    unblocked_d,
                    unblock_r,
                    regex_r,
                ) = extract_abp(unprocessed)
                blocked_domains.append(blocked_d)
                unblocked_domains.append(unblocked_d)
                unblock_rules.append(unblock_r)
                regex_rules.append(regex_r)
            if item[blg.i_key.format] == "domains":
                blocked_d, unblocked_d = extract_hosts(
                    unprocessed, item[blg.i_key.type]
                )
                blocked_domains.append(blocked_d)
                unblocked_domains.append(unblocked_d)

        item[blg.i_key.num_block_rules] = len(blocked_d) + len(regex_r)
        item[blg.i_key.num_unblock_rules] = len(unblock_r)
        write_file(blg.data_json, blg.file_json)

    blocked_domains = chain.from_iterable(blocked_domains)
    unblocked_domains = chain.from_iterable(unblocked_domains)
    unblock_rules = chain.from_iterable(unblock_rules)
    regex_rules = chain.from_iterable(regex_rules)

    return blocked_domains, unblocked_domains, unblock_rules, regex_rules


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
    if blg.category != "main":
        file_general_list = Path.joinpath(DirPath.output_filters, "main.txt")
        general_list = [x.strip() for x in read_file(file_general_list)]
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

    block_rules = "\n".join(block_rules) + "\n"
    unblock_rules = "\n".join(unblock_rules) + "\n"
    regex_rules = "\n".join(regex_rules) + "\n"

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


def gen_project_readme(list_source):
    """Generate README.md for aBL from category README.md files."""
    file_badges = is_path(Path.joinpath(DirPath.base, "BADGES.md"))
    file_about = is_path(Path.joinpath(DirPath.base, "ABOUT.md"))
    file_notes = is_path(Path.joinpath(DirPath.base, "NOTE.md"))
    main_title = markdown_strings.header(ListInfo.title, 1)
    badges = read_file(file_badges, data_type="str")
    about = read_file(file_about, data_type="str")
    notes = read_file(file_notes, data_type="str")
    info_add = markdown_strings.blockquote(
        "filter lists optimized for DNS level blocking of ads, "
        "analytics, crypto-jacking and other such threats/nuisances."
    )
    section = [
        main_title,
        info_add,
        badges or None,
        about or None,
        "\n".join(blocklist_section_table(list_source)),
        notes or None,
    ]
    data_md = "\n\n".join(filter(None, section)) + "\n\n"
    file_readme = is_path(Path.joinpath(DirPath.base, "README.md"))
    with open(file_readme, "w", encoding="utf-8") as file_output:
        file_output.writelines(data_md)
    concat_category(file_readme)


def run_hostlist_compiler(blg):
    """
    Generate filter list
    """
    file_config = is_path(f"{DirPath.hc_config}/config-{blg.category}.json")
    file_filter = is_path(Path.joinpath(blg.dir_output_filters, f"{blg.category}.txt"))
    hc_command = "hostlist-compiler -c " + str(file_config) + " -o " + str(file_filter)
    subprocess.check_call(hc_command, shell=True)


def extract_rules(content):
    block_rules, unblock_domains, unblock_rules, regex_rules = extract_abp(content)
    regex_rules = extract_regex(content)
    del unblock_domains
    return block_rules, unblock_rules, regex_rules


def read_filter(blg):
    file_filter = is_path(Path.joinpath(blg.dir_output_filters, f"{blg.category}.txt"))
    unprocessed = read_file(file_filter)
    block, unblock, regexp = extract_rules(unprocessed)
    block = [x.strip() for x in block]
    unblock = [x.strip() for x in unblock]
    regexp = [x.strip() for x in regexp]
    return block, unblock, regexp


def main():
    """
    Main
    """
    list_source = list(glob(f"{DirPath.input}/*.json"))
    list_source = sorted(list_source, key=lambda x: x)
    list_source = sorted(
        list_source, key=lambda x: x.__contains__("main"), reverse=True
    )
    if list_source:
        p_bar = tqdm(list_source, desc="Generating lists")
        list_title = []
        for i, file in enumerate(p_bar):
            li_ge = ListGenerator(
                file_json=file,
            )
            list_title.append(li_ge.data_json[li_ge.j_key.title])
            p_bar.set_description(
                desc=f"Processing sources — {li_ge.data_json[li_ge.j_key.title]}"
            )
            (
                blocked_domains,
                unblocked_domains,
                unblock_rules,
                regex_rules,
            ) = process_sources(li_ge)
            blocked_domains = list(blocked_domains)
            unblocked_domains = list(unblocked_domains)
            unblock_rules = list(unblock_rules)
            regex_rules = list(regex_rules)
            stats = {}
            num_unprocessed = {
                "unprocessed": len(blocked_domains)
                + len(unblock_rules)
                + len(regex_rules)
            }
            stats.update(num_unprocessed)
            blocked_domains = set(blocked_domains) - set(unblocked_domains)
            unblock_rules = set(unblock_rules)

            gen_filter_list(li_ge, blocked_domains, unblock_rules, regex_rules)
            run_hostlist_compiler(li_ge)
            block_rules, unblock_rules, regex_rules = read_filter(li_ge)
            block_rules = [
                x.replace("||", "").replace("^", "").replace("$important", "")
                for x in block_rules
            ]
            num_processed = gen_filter_list(
                li_ge, block_rules, unblock_rules, regex_rules
            )
            num_processed = {"processed": num_processed}
            stats.update(num_processed)
            gen_category(li_ge, stats)

            if i == len(list_source) - 1:
                p_bar.set_description(
                    desc=f"Generating README.md for the {li_ge.info.title}"
                )
                gen_project_readme(list_source)
                p_bar.set_description(desc="Done!")
    else:
        print("No sources to process!\nAdd json files to 'sources' directory.")


if __name__ == "__main__":
    main()

    
