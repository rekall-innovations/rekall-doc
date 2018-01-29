#!/bin/python

import argparse
import collections
import io
import yaml

#from rekall import plugins
from rekall import session
from rekall.ui import text

COLUMN_WIDTH = [30, 20, 40]
SOURCE_ROOT = "https://github.com/google/rekall/blob/master/"
LAYOUT = [
    ["Memory"],
    ["Memory", "Windows"],
    ["Memory", "Linux"],
    ["Memory", "OSX"],
    ["Live"],
    ["Live", "General"],
    ["Live", "API"],
    ["Filesystem"],
    ["Filesystem", "NTFS"],
    ["General"],
    ["General", "Utilities"],
]

rekall_session = session.Session()


def GenerateArgsTable(args):
    line_buffer = io.StringIO()
    renderer = text.TextRenderer(session=rekall_session, fd=line_buffer)
    boundary = "%s %s %s" % ("=" * COLUMN_WIDTH[0],
                             "=" * COLUMN_WIDTH[1],
                             "=" * COLUMN_WIDTH[2])
    with renderer:
        renderer.table_header([dict(name="Plugin", width=COLUMN_WIDTH[0]),
                               dict(name="Type", width=COLUMN_WIDTH[1]),
                               dict(name="Description", width=COLUMN_WIDTH[2])])

        for name, spec in sorted(args.items()):
            renderer.table_row(name,
                               spec["type"],
                               spec["help"])

    result = [boundary]
    result.extend(line_buffer.getvalue().splitlines())
    result.append(boundary)
    result[2] = boundary

    return result

def MaybeAddContent(result, name):
    try:
        # Leading spaces matter.
        result.extend([x.rstrip() for x in
                       open(name + ".rst", "rt").readlines()])
    except IOError:
        pass


def GenerateRST(api):
    result = []
    title = "%s (%s_)" % (api["name"], api["plugin"])
    result.append(".. _%s-%s-plugin:\n" % (api["name"], api["plugin"]))
    result.append(title)
    result.append("-" * len(title))
    result.append(api["description"])
    result.append("")

    if "args" in api:
        result.extend(GenerateArgsTable(api["args"]))
        result.append("")

    result.append(".. _%s: %s%s#L%s" % (api["plugin"], SOURCE_ROOT, api["source"],
                                      api["line_number"]))

    result.append("")

    MaybeAddContent(result, api["plugin"])

    return result

def ClassifyPlugin(api):
    modes = api["active_modes"]

    if "mode_live_api" in modes:
        return ["Live", "API"]

    if "mode_live" in modes:
        return ["Live", "General"]

    if "mode_windows_memory" in modes:
        return ["Memory", "Windows"]

    if "mode_linux_memory" in modes:
        return ["Memory", "Linux"]

    if "mode_darwin_memory" in modes:
        return ["Memory", "OSX"]

    if "mode_ntfs" in modes:
        return ["Filesystem", "NTFS"]

    return ["General", "Utilities"]


def RenderLayout(layout, headings, result):
    level_markings = ["=", "~", "_"]
    cursor = layout

    for heading in headings:
        cursor = cursor[heading]

    result.append(heading)
    result.append(level_markings[len(headings)] * len(heading))
    result.append("")

    if "_" in cursor:
        result.extend(cursor["_"])


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument(
        'api_file',
        default=None,
        help="Path to Rekall API file."
    )

    args = argument_parser.parse_args()
    data = yaml.safe_load(open(args.api_file).read())

    layout = collections.OrderedDict()
    for api in data:
        cursor = layout
        for level in ClassifyPlugin(api):
            cursor = cursor.setdefault(level, collections.OrderedDict())

        cursor.setdefault("_", []).extend(GenerateRST(api))

    result = ["Plugin Reference"]
    result.append("=" * len(result[0]))
    for headings in LAYOUT:
        RenderLayout(layout, headings, result)

    print("\n".join(result))
