# Copyright (C) 2013  ABRT Team
# Copyright (C) 2013  Red Hat, Inc.
#
# This file is part of faf.
#
# faf is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# faf is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with faf.  If not, see <http://www.gnu.org/licenses/>.

import re

from pyfaf.common import FafError
from pyfaf.proc import safe_popen

RE_ADDR2LINE_LINE1 = re.compile(r"^([_0-9a-zA-Z]+)(\+0x[0-9a-f]+)?"
                                 "( inlined at ([^:]+):([0-9]+) in (.*))?$")

RE_UNSTRIP_BASE_OFFSET = re.compile(r"^((0x)?[0-9a-f]+)")

def addr2line(binary_path, address, debuginfo_dir):
    """
    Calls eu-addr2line on a binary, address and directory with debuginfo.
    Returns an ordered list of triplets (function name, source file, line no).
    The last element is always the symbol given to retrace. The elements
    before are inlined symbols that should be placed above the given symbol
    (assuming that entry point is on the bottom of the stacktrace).
    """

    result = []
    child = safe_popen("eu-addr2line",
                       "--executable", binary_path,
                       "--debuginfo-path", debuginfo_dir,
                       "--functions", str(address))

    if child.returncode != 0:
        raise FafError("eu-add2line failed")

    line1, line2 = child.stdout.splitlines()
    line2_parts = line2.split(":", 1)
    line2_srcfile = line2_parts[0]
    line2_srcline = int(line2_parts[1])

    match = RE_ADDR2LINE_LINE1.match(line1)
    if match is None:
        raise FafError("Unexpected output from eu-addr2line: '{0}'"
                       .format(line1))

    if match.group(3) is None:
        funcname = match.group(1)
        srcfile = line2_srcfile
        srcline = line2_srcline
    else:
        funcname = match.group(6)
        srcfile = match.group(4)
        srcline = int(match.group(5))

        result.append((match.group(1), line2_srcfile, line2_srcline))

    result.append((funcname, srcfile, srcline))

    return result

def get_base_address(binary_path):
    """
    Runs eu-unstrip on a binary to get the address used
    as base for calculating relative offsets.
    """

    child = safe_popen("eu-unstrip", "-n", "-e", binary_path)

    if child.returncode != 0:
        raise FafError("eu-unstrip failed")

    match = RE_UNSTRIP_BASE_OFFSET.match(child.stdout)
    if match is None:
        raise FafError("Unexpected output from eu-unstrip: '{0}'"
                       .format(child.stdout))

    return int(match.group(1), 16)

def get_ssources_for_retrace(db, problemtype):
    return (db.session.query(SymbolSource)
                      .join(Symbol)
                      .join(ReportBtFrame)
                      .join(ReportBtThread)
                      .join(ReportBacktrace)
                      .join(Report)
                      .filter(Report.type == problemtype)
                      .filter((SymbolSource.symbol_id == None) |
                              (Symbol.name == "??") |
                              (SymbolSource.source_file == None) |
                              (SymbolSource.source_line == None)))

def shift_frames(db_thread, start=0, step=1):
    for db_frame in filter(lambda f: f.order >= start, db_thread.frames):
        db_frame.order += step

if __name__ == "__main__":
    print addr2line("/home/mtoman/debug/usr/lib/debug/lib/modules/3.9.4-301.fc19.x86_64/vmlinux", "0xffffffff8153c3ca", "/home/mtoman/debug/usr/lib/debug/")
    print get_base_address("/lib64/libgobject-2.0.so")
