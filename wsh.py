# encoding: utf-8

import glob
import base64
import os
import os.path as osp
import re
import time
import urllib


#{{{ utils
def catch_exc(default=None):
    def func(f):
        def _func(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except:
                return default
        return _func
    return func

#}}}

#{{{const
FLAG_MAP = {
    -1: "normal",
    1: "low",
    2: "medium",
    3: "high"
}

Regex = re.compile(r"(?si)(preg_replace.*\/e|`.*?\$.*?`|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)")
DBUrl = "https://raw.github.com/emposha/PHP-Shell-Detector/master/shelldetect.db"
FingerReg = re.compile('^(.+?)\[(.+?)\]\[(.+?)\]\[(.+?)\]')
#}}}


class PhpSerializer:
    def unserialize(self, s):
        return PhpSerializer._unserialize_var(self, s)[0]

    def _unserialize_var(self, s):
        return (
            {'i': PhpSerializer._unserialize_int
                , 'b': PhpSerializer._unserialize_bool
                , 'd': PhpSerializer._unserialize_double
                , 'n': PhpSerializer._unserialize_null
                , 's': PhpSerializer._unserialize_string
                , 'a': PhpSerializer._unserialize_array
            }[s[0].lower()](self, s[2:]))

    def _unserialize_int(self, s):
        x = s.partition(';')
        return (int(x[0]), x[2])

    def _unserialize_bool(self, s):
        x = s.partition(';')
        return (x[0] == '1', x[2])

    def _unserialize_double(self, s):
        x = s.partition(';')
        return (float(x[0]), x[2])

    def _unserialize_null(self, s):
        return (None, s)

    def _unserialize_string(self, s):
        (l, _, s) = s.partition(':')
        return (s[1:int(l) + 1], s[int(l) + 3:])

    def _unserialize_array(self, s):
        (l, _, s) = s.partition(':')
        a, k, s = {}, None, s[1:]

        for i in range(0, int(l) * 2):
            (v, s) = PhpSerializer._unserialize_var(self, s)

            if k:
                a[k] = v
                k = None
            else:
                k = v

        return (a, s[1:])


class Detector(object):

    def __init__(self, scan_path, db_path=None, scan_suffixes=("php", "asp", "txt", "jsp"), show_line=True):
        self.__scan_path = scan_path
        self.__db_path   = db_path or DBUrl
        self.__scan_suffixes = scan_suffixes
        self.__show_line   = show_line
        self.__finger_print = self.load_finter_print(self.__db_path)

    @catch_exc()
    def get_finger_content(self):
        if self.__db_path and osp.isfile(self.__db_path):
            with open(self.__db_path) as fp:
                return fp.read()
        return urllib.urlopen(self.__db_path).read()

    @catch_exc(default=[])
    def list_ext_files(self):
        if self.__scan_path and osp.isfile(self.__scan_path):
            if self.__scan_path.split('.')[-1] not in self.__scan_suffixes:
                return []
            return [self.__scan_path]

        paths = []
        if self.__scan_path and osp.isdir(self.__scan_path):
            for suffix in self.__scan_suffixes:
                globs = glob.glob("*.%s"%suffix)
                globs and paths.extend(globs)
        return paths

    @catch_exc(default={})
    def load_finter_print(self):
        """
        @return {fingerprint: (regex, shell_name)}
        """
        content = self.get_finger_content()
        if not content:
            return

        fingerprints = base64.decodestring(bytes(content))
        serial = PhpSerializer()
        fingerprints = serial.unserialize(str(fingerprints))

        results = {}
        for fpt, shell_name in fingerprints.iteritems():
            if fpt == "version":
                continue

            if "bb:" in fpt:
                fpt = base64.decodestring(bytes(fpt.replace('bb:', '')))

            results[fpt] = (re.compile(re.escape(fpt)), shell_name)
        return results

    def get_fileinfo(self, filename):
        mode, _, _, _, uid, gid, size, atime, mtime, ctime = os.stat(filename)
        return {
            "filename": filename,
            "filesize": size,
            "created_time": time.ctime(ctime),
            "last_modified": time.ctime(atime),
            "last_modified": time.ctime(mtime),
            "owner": "{0}:{1}".format(uid, gid),
            "perm": oct(mode)[-3:]
        }

    def _anaylize(self, filename):
        """
        {
            "filename": "",
            "filesize": "",
            "last_modified": "",
            "last_accessed": "",
            "owner": "",
            "perm":"",

            "alarm": "",
            "fingerprint": [{
                "name": "conf",
                "type": "asp",
                "flag": "",
                "rev":"",
            }],
            "suspicious": [
                {"line": 11, "func": []}
            ]
        }
        """
        content = None
        with open(filename, 'rb') as fp:
            content = fp.read()

        if not content:
            return {}

        match = Regex.findall(content)
        if not match:
            return {}

        result = self.get_fileinfo(filename)
        result["suspicious"] = []
        result["fingerprint"] = []
        result["alarm"] = "medium"   #normal, low, medium, high

        if self.__show_line:
            count  = 1
            lines = content.split("\n")

            for line in lines:
                lmatches = Regex.findall(line)
                if not lmatches:
                    continue
                result["suspicious"].append({"line": count, "func": lmatches})
                count += 1

        max_flag = 1
        for reg, shell in self.__finger_print:
            m = reg.findall(content)
            if not m:
                continue

            regex_shell = FingerReg
            match_shell = list(regex_shell.findall(shell)[0])
            flag = match_shell[2]
            if flag > max_flag:
                max_flag = flag

            result["finterprint"].append({
                "name": match_shell[0],
                "type": match_shell[3],
                "rev": match_shell[1],
                "flag": flag
            })

        result["alarm"] = FLAG_MAP.get(max_flag, "medium")
        return result

    def anaylize(self):
        for filename in self.list_ext_files():
            yield self._anaylize(filename)


def opt():
    import sys
    import pprint
    import optparse

    parser = optparse.OptionParser()
    parser.add_option( '--extension', '-e', type="string",
        dest="extension",
        default="php,txt,asp",
        help="file extensions that should be scanned, comma separated")
    parser.add_option( "-l", "--line", action="store_true",
        dest="line", default=False,
        help="show line number where suspicious function used")
    parser.add_option( '--path', '-p', type="string",
        dest="path",
        help="specify directory or file to scan")
    parser.add_option('--db', '-d', default="string",
        dest="db",
        help="shells signatures db, if None use remote")
    (options, args) = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        return
    suffixes = options.extension.split(",")
    suffixes = [s.strip() for s in suffixes]

    d = Detector(options.path, db_path=options.db, scan_suffixes=suffixes, show_line=options.line)
    for res in d.anaylize():
        pprint.pprint(res, indent=2)


if __name__ == '__main__':
    opt()
