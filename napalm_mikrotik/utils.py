import re

_TERSE_STATE = r"""
        \s*(?P<index>\d+)
        \s*(?P<state>[A-Z]*)\s*
        """

_TERSE_PAIR = r"""
        \s*(?P<key>.*?)
        \s*(?P<sep>=|:)\s*
        (?P<value>.*)$
        """

_UNIT_SPLIT = r"(?P<value>[\d\.]+)(?P<unit>\w+)"
UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB']


TERSE_STATE_RE = re.compile(_TERSE_STATE, re.VERBOSE)
TERSE_PAIR_RE = re.compile(_TERSE_PAIR, re.VERBOSE)
UNIT_SPLIT_RE = re.compile(_UNIT_SPLIT, re.VERBOSE)

EMPTY_LINE_RE = re.compile(r'^$')
START_FLAGS_RE = re.compile(r'^Flags:')
MK_COMMENT_RE = re.compile(
    r'^\s*(?P<index>\d+)\s*(?P<state>[A-Z]*)\s*(;;;(?P<comment>.*))$')
MK_COMMAND_RE = re.compile(r'([\w-]+)=')
MK_COUNTER_RE = re.compile(r'[\d\s]+')
MK_STRING_RE = re.compile(r'^"(.*)"$')


def to_seconds(time_format):
    seconds = minutes = hours = days = weeks = 0

    number_buffer = ''
    for current_character in time_format:
        if current_character.isdigit():
            number_buffer += current_character
            continue
        if current_character == 's':
            seconds = int(number_buffer)
        elif current_character == 'm':
            minutes = int(number_buffer)
        elif current_character == 'h':
            hours = int(number_buffer)
        elif current_character == 'd':
            days = int(number_buffer)
        elif current_character == 'w':
            weeks = int(number_buffer)
        else:
            raise ValueError(
                'Invalid specifier - [{}]'.format(current_character))
        number_buffer = ''

    seconds += (minutes * 60)
    seconds += (hours * 3600)
    seconds += (days * 86400)
    seconds += (weeks * 604800)

    return seconds


def bytes_to_human(value):
    for unit in UNITS:
        if abs(value) < 1024.0:
            return "%3.1f%s" % (value, unit)
        value /= 1024.0
    else:
        return "%3.1f%s" % (value, UNITS[-1])


def human_to_bytes(value):
    result = .0

    mo = UNIT_SPLIT_RE.match(value)
    if mo:
        value, unit = mo.group('value', 'unit')

        result = float(value)
        if unit in UNITS:
            result = result * (1 << 10 * UNITS.index(unit))

    return result


def parse_output(output):
    result = dict()

    for line in output.splitlines():
        TERSE_PAIR_RE.match(line)
        mo = TERSE_PAIR_RE.match(line)
        if mo:
            key, sep, value = mo.group('key', 'sep', 'value')
            result.setdefault(key, value)

    return result


def parse_terse_output(output):
    result = []

    for line in output.strip().splitlines():
        new_item = {}
        items = MK_COMMAND_RE.split(line)

        first = items.pop(0)
        mo = TERSE_STATE_RE.search(first)
        if mo:
            new_item['_index'] = int(mo.group('index'))
            new_item['_flags'] = tuple(mo.group('state'))

        while len(items) > 1:
            key = items.pop(0).strip()
            value = items.pop(0).strip()
            new_item.setdefault(key, value)

        result.append(new_item)

    return result


def parse_detail_output(output):
    result = []
    first_line = False

    new_item = None
    for line in output.splitlines():
        if EMPTY_LINE_RE.match(line):
            result.append(new_item)
            new_item = {}
            continue

        if not first_line and START_FLAGS_RE.search(line):
            first_line = True
            continue

        if not new_item:
            new_item = {}

        mo = MK_COMMENT_RE.match(line)
        if mo:
            if new_item:
                result.append(new_item)
                new_item = {}
            new_item['_index'] = int(mo.group('index'))
            new_item['_flags'] = tuple(mo.group('state'))
            new_item['comment'] = mo.group('comment').strip()
            continue

        items = MK_COMMAND_RE.split(line)

        first = items.pop(0)
        mo = TERSE_STATE_RE.search(first)
        if mo:
            new_item['_index'] = int(mo.group('index'))
            new_item['_flags'] = tuple(mo.group('state'))

        while len(items) > 1:
            key = items.pop(0).strip()
            value = items.pop(0).strip()

            if MK_COUNTER_RE.match(value):
                value = int(value.replace(' ', ''))
            elif MK_STRING_RE.match(value):
                value = value.strip('"')

            new_item.setdefault(key, value)

    if new_item:
        result.append(new_item)

    return result
