import json
from pathlib import Path
from progiter import ProgIter

from generator.generator_functions import process_sources, remove_duplicates_false, remove_redundant
from generator.generator_helper_functions import read_file, write_file

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


class Generator(object):
    list_sources = list(Path.glob(INPUT_DIR, '*.json'))

    def __init__(self, file_json):
        """

        :param file_json: the category source json file
        """
        self.file_json = file_json
        self.category = Path(file_json).stem
        self.data_json = read_file(file_json)
        self.j_key = JSONKey
        self.i_key = ITEMKey


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
            desc=f"Processing sources for category: {blg.category}", refresh=True
        )
        blocked, unblocked = process_sources(blg)

        if blocked:
            progress_bar.set_description(
                desc=f"Removing duplicates & false positives for category: {blg.category}",
                refresh=True,
            )
            blocked, stats = remove_duplicates_false(blocked, unblocked)
            progress_bar.set_description(
                desc=f"Removing redundant sub-domains for category: {blg.category}", refresh=True
            )
            blocked, stats = remove_redundant(blocked, stats)

        blocked = [x + '\n' for x in blocked]
        unblocked = [x + '\n' for x in unblocked]
        write_file(blocked, 'blocked.txt')
        write_file(unblocked, 'unblocked.txt')


if __name__ == "__main__":
    main()
