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

import multiprocessing
from pyfaf.actions import Action
from pyfaf.problemtypes import problemtypes
from pyfaf.queries import get_ssources_for_retrace


class Retrace(Action):
    name = "retrace"

    def __init__(self):
        super(Retrace, self).__init__()

    def run(self, cmdline, db):
        if len(cmdline.problemtype) < 1:
            types = problemtypes.keys()
        else:
            types = cmdline.problemtype

        for problemtype in types:
            if problemtype not in problemtypes:
                self.log_warn("Problem type '{0}' is not supported"
                              .format(problemtype))
                continue

            problemplugin = problemtypes[problemtype]
            self.log_info("Retracing '{0}' problems".format(problemtype))

            self.log_info("Preparing debuginfo map")
            tasks = {}
            for db_ssource in get_ssources_for_retrace(db, problemtype):
                dbginfos = problemplugin.get_dbginfos_for_ssource(db,
                                                                  db_ssource)
                if len(dbginfos) < 1:
                    self.log_warn("No debuginfo found for {0} ({1})"
                                  .format(db_ssource.path, db_ssource.build_id))
                    continue

                for debuginfo in dbginfos:
                    pkg = problemplugin.get_pkg_for_file(db, db_ssource.path,
                                                         debuginfo.build)
                    if pkg is None:
                        self.log_warn("No matching binary package found for "
                                      "{0} ({1})".format(db_ssource.path,
                                                         db_ssource.build_id))
                        continue

                    if debuginfo not in tasks:
                        tasks[debuginfo] = {}

                    if pkg not in tasks[debuginfo]:
                        tasks[debuginfo][pkg] = set()

                    tasks[debuginfo][pkg].add(db_ssource)

    def tweak_cmdline_parser(self, parser):
        parser.add_problemtype(multiple=True)
        parser.add_argument("--workers", type=int,
                            default=multiprocessing.cpu_count,
                            help="unpack packages in parallel")
