from concurrent.futures.thread import ThreadPoolExecutor
from itertools import chain
import regex as re
from progiter import ProgIter

from generator.generator_helper_functions import (
    get_content,
    extract_abp,
    extract_hosts,
    write_file,
    get_last_modified,
    get_cname,
    extract_tld,
    match_pattern,
)


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


def remove_redundant(blocked, stats):
    """
    Removes sub-domains if main-domain is already in the list

    :param blocked: the input list of blocked domains
    :param stats: statistics
    :return: blocked domains without redundant subdomains, updated statistics
    """

    main_domains = [
        item
        for item in ProgIter(blocked, desc="Identifying main-domains")
        if not extract_tld(item).subdomain
    ]

    pattern_if_sub = re.compile("|".join(f"(?:.*({p})$)" for p in main_domains))

    matched, unmatched = match_pattern(
        blocked, pattern_if_sub, "Scanning for redundant sub-domains"
    )
    del matched
    blocked = list(chain(unmatched, main_domains))

    num_blocked_domains = {"minus redundant sub-domains": len(blocked)}
    stats.update(num_blocked_domains)

    return blocked, stats
