"""Keep untrusted CSV text from becoming spreadsheet formulas."""

from mosp.security.regex import scan_pattern

# Importers differ in what they skip before a cell's first character, so a
# formula is looked for past all of these.
_SKIPPED = " \t\r\n\v\f\x00\ufeff"

# A spreadsheet that takes semicolons or tabs as its column separator, as
# several locales do when a .csv file is opened directly, splits a cell there
# whatever the file's own delimiter and quoting. Such a reader does not see
# the quote that opens a comma-separated field either, so a line break inside
# a value can end its row and begin another. A formula could so begin in the
# middle of a cell the application wrote. What follows a separator is skipped
# as the start of a value is.
_FORMULA_AFTER_SEPARATOR = scan_pattern(
    r"([;\t\r\n][ \t\r\n\v\f\x00\ufeff]*+)(?=[=+\-@])"
)


def spreadsheet_cell(value):
    if not isinstance(value, str):
        return value
    # Each part such a reader would make into a cell of its own, after a
    # separator or a line break, is guarded like the start of the cell.
    value = _FORMULA_AFTER_SEPARATOR.sub(r"\1'", value)
    probe = value.lstrip(_SKIPPED)
    if probe.startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value
