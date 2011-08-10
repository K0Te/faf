# Various helpers shared by command line tools.
# Copyright (C) 2011 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import config
import subprocess
import sys
import cache
import types
import datetime
import signal
import time
import os

class Alarm(Exception):
    pass
def alarm_handler(signum, frame):
    raise Alarm

def process(args, stdout=None, stderr=None, inputt=None,
            timeout=None, timeout_attempts=0, returncode_attempts=0):
    proc = subprocess.Popen(args, stdout=stdout, stderr=stderr)
    if timeout is not None:
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(timeout)
    try:
        retstdout, retstderr = proc.communicate(inputt)
        signal.alarm(0)  # reset the alarm
    except Alarm:
        try:
            proc.terminate()
        except OSError:
            pass
        if timeout_attempts > 0:
            time.sleep(60) # wait a minute before another attempt
            return process(args, stdout, stderr, inputt, timeout,
                           timeout_attempts - 1, returncode_attempts)
        else:
            sys.stderr.write("Program exited with timeout: {0}.\n".format(args))
            exit(1)
    if proc.returncode != 0:
        if returncode_attempts > 0:
            time.sleep(60) # wait a minute before another attempt
            return process(args, stdout, stderr, inputt, timeout,
                           timeout_attempts, returncode_attempts - 1)
        else:
            sys.stderr.write("Unexpected return code {0} from {1}.\n".format(proc.returncode, args))
            exit(1)
    return retstdout.decode('utf-8') if retstdout is not None else None, retstderr.decode('utf-8') if retstderr is not None else None

def config_get(option):
    """
    Returns user's configuration value for an option.
    Option is in "Section.OptionName" format. Example: "Bugzilla.User".

    This function returns either None in the case of failure, or a
    string containing the option value.
    """
    try:
        args = ["faf-config", "--get", option]
        process = subprocess.Popen(args, stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return stdout.strip("\n \t")
    except OSError as exception:
        sys.stderr.write("Failed to run the command: faf-config.\n")
        exit(1)
    return None # be explicit here

def config_get_cache_directory():
    return os.path.expanduser(config_get("Cache.Directory"))

def config_get_cache_database_path():
    return os.path.join(config_get_cache_directory(), "sqlite.db")

def cache_list_id(target):
    args = ["faf-cache", "list", target, "--format", "%id"]
    cache_proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    list_text = cache_proc.communicate()[0].decode('utf-8')
    if cache_proc.returncode != 0:
        sys.stderr.write("Failed to get {0} list from cache.\n".format(target))
        exit(1)
    return [int(item) for item in list_text.splitlines()]

def cache_list_id_mtime(target):
    """Returns a pair list_if_ids, dict_id_to_mtime"""
    args = ["faf-cache", "list", target, "--format", "%id %mtime"]
    cache_proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    list_text = cache_proc.communicate()[0].decode('utf-8')
    if cache_proc.returncode != 0:
        sys.stderr.write("Failed to get {0} list from cache.\n".format(target))
        exit(1)
    entry_ids = []
    times = {}
    for entry in list_text.splitlines():
        entry_id, timestamp = entry.split()
        entry_ids.append(int(entry_id))
        times[int(entry_id)] = datetime.datetime.fromtimestamp(float(timestamp))
    return entry_ids, times

def cache_get(target, entry_id, parser_module=None, failure_allowed=False):
    args = ["faf-cache", "show", str(target), str(entry_id)]
    cache_proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    entry_text = cache_proc.communicate()[0].decode('utf-8')
    if cache_proc.returncode != 0:
        if failure_allowed:
            return None
        sys.stderr.write("Failed to get {0} #{1} from cache.\n".format(target, entry_id))
        exit(1)
    if parser_module is None:
        parser_module = cache.__dict__[target.replace("-", "_")]
    return parser_module.parser.from_text(entry_text)

def cache_get_path(target, entry_id):
    args = ["faf-cache", "show", str(target), str(entry_id), "--path"]
    cache_proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    path = cache_proc.communicate()[0].decode('utf-8')
    if cache_proc.returncode != 0:
        sys.stderr.write("Failed to get {0} #{1} path from cache.\n".format(target, entry_id))
        exit(1)
    return path.strip()

def cache_add(entry, overwrite, target=None):
    # Find target's parser from cache, depending on the class of entry
    for cache_item, cache_item_object in cache.__dict__.items():
        if not type(cache_item_object) is types.ModuleType:
            continue
        for potential_class in cache_item_object.__dict__.values():
            if not type(potential_class) is types.ClassType:
                continue
            if not isinstance(entry, potential_class):
                continue
            if "parser" not in cache_item_object.__dict__:
                sys.stderr.write("Failed to find parser for module {0}.\n".format(cache_item))
                exit(1)
            entry_text = cache_item_object.__dict__["parser"].to_text(entry)
            if target is None:
                target = cache_item.replace("_", "-")
            args = ["faf-cache", "add", target, str(entry.id)]
            if overwrite:
                args.append("--overwrite")
            cache_proc = subprocess.Popen(args, stdin=subprocess.PIPE)
            cache_proc.communicate(entry_text)
            if cache_proc.returncode != 0:
                sys.stderr.write("Failed to store {0} to cache.\n".format(target))
                sys.stderr.write("Return code: {0}\n".format(cache_proc.returncode))
                exit(1)
            return
    sys.stderr.write("Failed to find corresponding module for {0}.\n".format(entry))
    exit(1)

def cache_add_text(text, entry_id, target, overwrite):
    args = ["faf-cache", "add", str(target), str(entry_id)]
    if overwrite:
        args.append("--overwrite")
    cache_proc = subprocess.Popen(args, stdin=subprocess.PIPE)
    cache_proc.communicate(text)
    if cache_proc.returncode != 0:
        sys.stderr.write("Failed to store {0} #{1} to cache.\n".format(target, entry_id))
        sys.stderr.write("Return code: {0}\n".format(cache_proc.returncode))
        exit(1)

def cache_remove(target, entry_id):
    args = ["faf-cache", "remove", target, str(entry_id)]
    cache_proc = subprocess.Popen(args)
    cache_proc.communicate()
    if cache_proc.returncode != 0:
        sys.stderr.write("Failed to remove {0} #{1} from cache.\n".format(target, entry_id))
        sys.stderr.write("Return code: {0}\n".format(cache_proc.returncode))
        exit(1)