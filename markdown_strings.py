"""markdown_strings
Modified from https://github.com/awesmubarak/markdown_strings
Markdown is a markup language with plain text formatting syntax. This package
allows the creation of markdown-compliant strings. For information about
markdown see:

-   http://commonmark.org/
-   https://daringfireball.net/projects/markdown/

"""

# Helper functions


def esc_format(text):
    """Return text with formatting escaped."""
    return str(text).replace("_", r"\_").replace("*", r"\*")


def header(header_text, header_level, style="atx"):
    """Return a header of specified level."""
    # check types
    if not isinstance(header_level, int):
        raise TypeError("header_level must be int")
    if not isinstance(header_text, str):
        raise TypeError("header_text must be str")
    # specifics for each style
    if style == "atx":
        if not 1 <= header_level <= 6:
            raise ValueError(f"Invalid level {header_level} for atx")
        return f"{'#' * header_level} {esc_format(header_text)}"
    elif style == "setext":
        if not 0 < header_level < 3:
            raise ValueError(f"Invalid level {header_level} for setext")
        header_character = "=" if header_level == 1 else "-"
        header_string = (header_character * 3) + header_character * (
            len(header_text) - 3
        )
        return f"{esc_format(header_text)}\n{header_string}"
    else:
        raise ValueError(f"Invalid style {style} (choose 'atx' or 'setext')")


def italics(text):
    """Return italics formatted text."""
    return f"_{esc_format(text)}_"


def bold(text):
    """Return bold formatted text."""
    return f"**{esc_format(text)}**"


def inline_code(text):
    """Return formatted inline code."""
    return f"`{str(text)}`"


def code_block(text, language=""):
    """Return a code block."""
    if language:
        return f"```{language}\n{text}\n```"
    return "\n".join([f"    {item}" for item in text.split("\n")])


# Links


def link(text, link_url):
    """Return an inline link."""
    return f"[{esc_format(text)}]({link_url})"


def image(alt_text, link_url, title=""):
    """Return an inline image."""
    image_string = f"![{esc_format(alt_text)}]({link_url})"
    if title:
        image_string += f' "{esc_format(title)}"'
    return image_string


# Lists


def unordered_list(text_list):
    """Return an unordered list from an list."""
    return "\n".join([f"-   {esc_format(item)}" for item in text_list])


def ordered_list(text_list):
    """Return an ordered list from an list."""
    ordered_list = [
        f"{f'{esc_format(number + 1)}.'.ljust(3)} {esc_format(item)}"
        for number, item in enumerate(text_list)
    ]

    return "\n".join(ordered_list)


# Miscellaneous


def blockquote(text):
    """Return a blockquote."""
    return "\n".join([f"> {esc_format(item)}" for item in text.split("\n")])


def horizontal_rule(length=79, style="_"):
    """Return a horizontal rule."""
    if style not in ("_", "*"):
        raise ValueError("Invalid style (choose '_' or '*')")
    if length < 3:
        raise ValueError("Length must be >= 3")
    return style * length


# Non-standard markdown


def strikethrough(text):
    """Return text with strike-through formatting."""
    return f"~{esc_format(text)}~"


def task_list(task_list):
    """Return a task list."""
    tasks = [
        f"- [{'X' if completed else ' '}] {esc_format(item)}"
        for item, completed in task_list
    ]

    return "\n".join(tasks)


# Tables


def table_row(text_list, pad=-1):
    """Return a single table row."""
    if pad == -1:
        pad = [0] * len(text_list)
    row = "|"
    for column_number in range(len(text_list)):
        padding = pad[column_number] + 1
        row += (" " + str(text_list[column_number])).ljust(padding) + " |"
    return row


def table_delimiter_row(number_of_columns, column_lengths=-1):
    """Return a delimiter row for use in a table."""
    if column_lengths == -1:
        column_lengths = [0] * number_of_columns
    # error checking
    if number_of_columns != len(column_lengths):
        raise ValueError(
            "number_of_columns must be the number of columns in column_lengths"
        )
    # creating the list with the right number of dashes
    delimiter_row = [
        "---" + "-" * (column_lengths[column_number] - 3)
        for column_number in range(number_of_columns)
    ]

    # use table row for acctually creating the table row
    return table_row(delimiter_row)


def table(table_list):
    """Return a formatted table, generated from lists representing columns."""
    number_of_columns = len(table_list)
    number_of_rows_in_column = [len(column) for column in table_list]
    string_list = [[str(cell) for cell in column] for column in table_list]
    column_lengths = [len(max(column, key=len)) for column in string_list]
    table = []

    # title row
    row_list = [column[0] for column in string_list]
    table.append(table_row(row_list, pad=column_lengths))

    # delimiter row
    table.append(
        table_delimiter_row(len(column_lengths), column_lengths=column_lengths)
    )

    # body rows
    for row in range(1, max(number_of_rows_in_column)):
        row_list = []
        for column_number in range(number_of_columns):
            if number_of_rows_in_column[column_number] > row:
                row_list.append(string_list[column_number][row])
            else:
                row_list.append("")
        table.append(table_row(row_list, pad=column_lengths))
    return "\n".join(table)


def table_from_rows(table_list):
    """Return a formatted table, using each list as the list."""
    # transpose the list
    number_of_rows = len(table_list)
    transposed = []
    for column_number in range(0, number_of_rows):
        column_list = [row[column_number] for row in table_list]

        transposed.append(column_list)

    return table(transposed)
