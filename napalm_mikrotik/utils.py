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
UNITS = ['B','KiB', 'MiB', 'GiB', 'TiB']


TERSE_STATE_RE = re.compile(_TERSE_STATE, re.VERBOSE)
TERSE_PAIR_RE  = re.compile(_TERSE_PAIR, re.VERBOSE)
UNIT_SPLIT_RE  = re.compile(_UNIT_SPLIT, re.VERBOSE)

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

        mo = TERSE_STATE_RE.search(line)
        if mo:
            index, state = mo.group('index', 'state')
            new_item['_index'] = int(index)
            new_item['_flags'] = tuple(state)

        for item in line.split(' '):
            mo = TERSE_PAIR_RE.match(item)
            if mo:
                key, sep, value = mo.group('key', 'sep', 'value')
                new_item.setdefault(key, value)

        result.append(new_item)

    return result
