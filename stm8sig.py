# -*- coding: utf-8 -*-

import sys
import os
import tempfile
import subprocess
import re
from copy import deepcopy
from enum import Enum

from collections import OrderedDict

# Replace ?b ?w ?l ?e with fixed addresses
vregsfixed = True

# Store hex dump
storehex = not True

# store lib.o files
storearchive = not True

# store lib.txt dump files
storedump = not True

dolog = True

stm8tool_iarchive = r"C:\Program Files (x86)\IAR Systems\Embedded Workbench 8.3\stm8\bin\iarchive.exe"
stm8tool_ielfdump = r"C:\Program Files (x86)\IAR Systems\Embedded Workbench 8.3\stm8\bin\ielfdumpstm8.exe"
idatool_sigmake = r"D:\flair68\bin\win\sigmake.exe"


def log(*message):
    if dolog:
        message = [str(m) for m in message]
        # print(', '.join(message))
        print(*message)


class Code:

    def __init__(self, secnum, libname):
        self.secnum = secnum
        self.libname = libname

        self.hex = []
        self.dump = {}  # offset -> {'hex': chunk, 'labels': [], 'ref: []'}
        self.labels = []
        self.refnames = []  # list of ({'offset', 'len', 'addend', 'symbol', 'global'})
        self.nubbles = []
        self.pat = []

    def AddLabel(self, name):
        # log('AddLabel', name)
        if name.startswith('`') and name.endswith('`'):
            name = name[1:-1]
        self.labels.append(name)

    def AddCode(self, offset, dump, instruction, args):
        offset = int(offset, 16)
        # log('AddCode:', offset, dump, instruction, args)
        assert len(dump) % 2 == 0, r'Incorrect len'
        assert not offset in self.dump, r'Duplicate offset'
        hex = re.findall(r'..', dump)
        self.dump[offset] = {'hex': hex, 'labels': self.labels, 'code': (instruction, args)}
        self.labels = []

    def AddHex(self, offset, dump):
        if storehex:
            offset = int(offset, 16)
            data = dump[:16 * 3].strip().split(' ')
            assert offset == len(self.hex), r'Invalid offset in hex dump'
            self.hex.extend(data)

    def AddReloc(self, offset, type, addend, symbol, section):
        offset = int(offset, 16)
        addend = int(addend, 16)
        if addend & 0x80000000 != 0: addend = addend - 0x100000000  # addend is signed DWORD
        # log('AddReloc', offset, type, addend, symbol, section)
        # R_STM8_DIR8, R_STM8_DIR16, R_STM8_DIR24 - просто замена 1byte, 2bytes, 3bytes
        # R_STM8_PCREL8 - ? относительная короткая ссылка. Чаще локальная ссылка, но может указывать и на глобальное имя
        # R_STM8_DIR16_LWRD - ? ссылка на локальную ф-ию, для которой не хватило места в относительной ссылке
        # R_STM8_NONE - ? Похоже на разделение кода на несколько кусков, которые надо разделить
        # R_STM8_DIR8_BYTE1, R_STM8_DIR8_BYTE2, R_STM8_DIR8_BYTE3 - замена по 1 байту из 3хбайтной ссылки
        #   напрямую референсные ссылки не получатся, todo: Попытаться пихнуть их как локальные ссылки, IDA может добавит их как коммент
        #   example: offset = 0x123456
        #   xxR_STM8_DIR8_BYTE3xx -> xx12xx
        #   xxR_STM8_DIR8_BYTE2xx -> xx34xx
        #   xxR_STM8_DIR8_BYTE1xx -> xx56xx
        l = 0
        asglob = True if section == 'Ext' else False
        if type in ['R_STM8_DIR8']:
            l = 1
        elif type in ['R_STM8_PCREL8']:
            l = 1
        elif type in ['R_STM8_DIR8_BYTE1', 'R_STM8_DIR8_BYTE2', 'R_STM8_DIR8_BYTE3']:
            l = 1
            asglob = False
        elif type in ['R_STM8_DIR16', 'R_STM8_DIR16_LWRD']:
            l = 2
        elif type in ['R_STM8_DIR24']:
            l = 3
        elif type in ['R_STM8_DIR32']:
            l = 4
        elif type in ['R_STM8_NONE']:
            # ? todo
            l = 0
        else:
            log('SKIP: unknown type', type)
        if l > 0:
            self.refnames.append(({'offset': offset, 'len': l, 'addend': addend, 'symbol': symbol, 'global': asglob}))

    def Complete(self):
        if not self.dump:
            if not self.hex:
                return
            # hex to dump
            self.dump = {0: {'hex': self.hex, 'labels': [], 'code': ('', '')}}

        # sort by address
        self.dump = {k: self.dump[k] for k in sorted(self.dump)}
        # self.dump = OrderedDict({k: self.dump[k] for k in sorted(self.dump)})

        # and check lenght of chunks
        n = 0
        for o in self.dump:
            dl = len(self.dump[o]['hex'])
            t = o + dl
            if n != o:
                log(r'None code at {0:06X} - {1:06X}'.format(n, o - 1))
            n = t

        # check refs
        for r in self.refnames:
            do = r['offset']
            while do >= 0 and not do in self.dump:
                do -= 1
            if do < 0 or r['offset'] >= do + len(self.dump[do]['hex']):
                log(r'Skip ref out of range at {0:06X}, len={1}, name={2}, global={3}'.format(r['offset'], r['len'],
                                                                                              r['symbol'], r['global']))
                continue
            r['offset'] -= do
            self.dump[do].setdefault('ref', []).append(r)
            assert r['offset'] + r['len'] <= len(self.dump[do]['hex']), r'Ref out of rande'
        self.refnames = []

        # split the dump into nubbles
        o = 0
        while o is not None:
            o = self.SplitDump(o)

        # build pat for every nubble
        for nubble in self.nubbles:
            pattern, gnames, rnames = self.BuildPat(nubble)
            pppp = ''.join(pattern)
            gggg = ' '.join(gnames)
            rrrr = ' '.join(rnames)

            ll = '00'
            ssss = '0000'
            LLLL = '{0:04X}'.format(len(pattern))
            pppp = ''.join(pppp).ljust(64, '.')
            tttt = pppp[64:]
            pppp = pppp[:64]
            pat = '{0} {1} {2} {3} {4} {5} {6}'.format(pppp, ll, ssss, LLLL, gggg, rrrr, tttt)
            self.pat.append(pat)

    def Decorate_far_func(self, symbol):
        # if re.match(r'\.far_func\.text_\d+', symbol) or re.match(r'\.near_func\.text\d+', symbol):
        if re.match(r'\.(far|near)_func\.text_?\d+', symbol):
            return self.libname+symbol
        else:
            return None

    def GetFixedAddress(self, symbol):
        vregs = {'?b0': 0x00, '?b1': 0x01, '?b2': 0x02, '?b3': 0x03, \
                 '?b4': 0x04, '?b5': 0x05, '?b6': 0x06, '?b7': 0x07, \
                 '?b8': 0x08, '?b9': 0x09, '?b10': 0x0a, '?b11': 0x0b, \
                 '?b12': 0x0c, '?b13': 0x0d, '?b14': 0x0e, '?b15': 0x0f, \
                 '?w0': 0x00, '?w1': 0x02, '?w2': 0x04, '?w3': 0x06, \
                 '?w4': 0x08, '?w5': 0x0a, '?w6': 0x0c, '?w7': 0x0e, \
                 '?l0': 0x00, '?l1': 0x04, '?l2': 0x08, '?l3': 0x0c, \
                 '?e0': 0x01, '?e1': 0x05, '?e2': 0x09, '?e3': 0x0d}
        if vregsfixed and symbol in vregs:
            return vregs[symbol]
        else:
            return None

    def GetRelocPattern(self, offset, symbol, addend, slice):
        l = len(slice)
        f = self.GetFixedAddress(symbol)
        if f is not None:
            # f = int(''.join(slice), 16)
            f += addend
            slice = re.findall('..', '{1:0{0}X}'.format(l * 2, f))
        else:
            for i in range(l):
                assert slice[i] == '00', r'NOT 00 at 0x{:06X}'.format(offset + i)  # posible is ok?
                slice[i] = '..'
        return slice

    def GetGlobName(self, labels, offset):
        # Оставить только 1 глобальное имя, иначе None
        glabels = []
        for l in labels:
            if l == '$t': continue
            if l == '$d': continue
            if re.match(r'\[symbol #\d+\]', l): continue
            if l == '??call_ctors': continue
            # if l == '__iar_section$$root': continue
            glabels.append(l)

        if len(glabels) > 1:
            #log(r'Multiple labels {} at 0x{:04X}'.format(glabels, offset))
            ll = [l for l in glabels if not self.Decorate_far_func(l)]
            if len(ll) > 0:
                glabels = ll
            if len(glabels) > 1:
                log(r'Multiple labels {} at 0x{:04X}'.format(glabels, offset))
        return glabels

    def GetBreakCmd(self, code):
        if code[0] == 'RET': return True
        if code[0] == 'RETF': return True
        if code[0] == 'JRA': return True
        return False

    def SplitDump(self, start):
        nubble = {}
        nextep = None
        lastcmdbreak = None
        for offset, cmd in self.dump.items():
            if offset < start: continue
            label = self.GetGlobName(self.dump[offset]['labels'], offset)
            if label and nextep is None and offset > start:
                nextep = offset
            if label and lastcmdbreak:
                self.nubbles.append(nubble)
                return nextep
            lastcmdbreak = self.GetBreakCmd(self.dump[offset]['code'])
            nubble[offset] = deepcopy(self.dump[offset])
            nubble[offset]['labels'] = label    # global names only
        self.nubbles.append(nubble)
        return nextep

    def BuildPat(self, nubble):
        pattern = []
        gnames = []
        rnames = []
        poffset = 0
        for offset, b in nubble.items():
            # Add names
            for label in b['labels']:

                l = self.Decorate_far_func(label)
                if not l:
                    gnames.append(r':{0:04X} {1}'.format(poffset, label))
                else:
                    gnames.append(r':{0:04X}@ {1}'.format(poffset, l))

                # is_global = not label.startswith(r'.far_func.')
                # if is_global:
                #     gnames.append(r':{0:04X} {1}'.format(poffset, label))
                # else:
                #     gnames.append(r':{0:04X}@ {1}{2}'.format(poffset, self.libname, label))

            hex = b['hex']
            for r in b.get('ref', []):
                roffset = r['offset']
                rlen = r['len']
                rsymbol = r['symbol']
                raddend = r['addend']
                rglob = r['global']

                # Add pattern
                slice = hex[roffset:roffset + rlen]
                slice = self.GetRelocPattern(offset + roffset, rsymbol, raddend, slice)
                hex[roffset:roffset + rlen] = slice

                # Add ref names
                s = self.Decorate_far_func(rsymbol)
                if not s:
                    f = self.GetFixedAddress(rsymbol)
                    # if f is None and rglob:
                    if f is None:
                        s = rsymbol

                if s:
                    rnames.append(r'^{0:04X} {1}'.format(poffset + roffset, s))
                else:
                    if f is None:
                        log('Skip ref name', r)

                # if (f is None and rglob) or statsymbol:
                #     rnames.append(r'^{0:04X} {1}'.format(poffset + roffset, rsymbol))
                # else:
                #     if f is None:
                #         log('Skip ref name', r)

            pattern += hex
            poffset += len(hex)

        if gnames == [] and rnames == []:   # todo fix
            gnames.append(r':{0:04X} #{1}'.format(poffset, str(self.secnum)))
        return pattern, gnames, rnames





class ElfContentParser:

    class Sect(Enum):
        other = 0
        code = 1
        reloc = 2

    def __init__(self, libname, content):
        self.pat = []
        self.libname = libname
        self.code: Code = None
        self.__sect = self.Sect.other

        log(self._Get_TitleLog())
        if storedump:
            txtfile = libname + '.txt'
            if not os.path.isfile(txtfile):
                with open(libname + '.txt', "w") as file:
                    file.write(content)
                    file.close()
            else:
                log(r'{} not save'.format(txtfile))

        lines = content.splitlines()
        for line in lines:
            self.__NextLine(line)
        self.__Store()

    def _Get_TitleLog(self):
        return r'Processing libdump {}'.format(self.libname)

    def __Store(self):
        if self.code:
            self.code.Complete()
            self.pat.extend(self.code.pat)

    def __NextLine(self, line):
        if line.lstrip().startswith('#'):
            # Is Comment
            self.__SkipLine(line)
            return
        r = re.match(r'Section #(\d+) (.*):', line)
        if r:
            # Is Section
            secnum = r.group(1)
            secname = r.group(2)
            if secname in [r'.far_func.text', r'.near_func.text', r'.near.rodata']:
                self.__Store()
                # секция кода может быть без секции reloaction, тогда секции кода будут идти подряд
                # assert self.__sect != self.Sect.code, r'Double code section'
                self.__sect = self.Sect.code
                self.code = Code(secnum, self.libname)
            elif secname in [r'.rela.far_func.text', r'.rela.near_func.text']:
                assert self.__sect != self.Sect.reloc, r'Double relocation section'
                self.__sect = self.Sect.reloc
            else:
                self.__sect = self.Sect.other
                self.__SkipLine(line)
        else:
            if self.__sect == self.Sect.code:
                r = re.match(r'\s*(0x[0-9A-Fa-f]+):\s+(.*)', line)
                if r:
                    # Is hex dump
                    self.code.AddHex(r[1], r[2])
                else:
                    s = line.strip()
                    if s.endswith(':'):
                        # Is Label
                        s = s[:-1]
                        self.code.AddLabel(s)
                    else:
                        r = re.match(r'\s*([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+(\S+)\s*(.*)', line)
                        if r:
                            # Is Code
                            self.code.AddCode(r.group(1), r.group(2), r.group(3), r.group(4))
                        else:
                            self.__SkipLine(line)
            elif self.__sect == self.Sect.reloc:
                r = re.match(r'\s*(\d+)\s+(0x[0-9A-Fa-f]+)\s+(\d+)\s+(\w+)\s+(0x[0-9A-Fa-f]+)\s+(\d+)\s+(\S+)\s+(.+)',
                             line)
                if r:
                    self.code.AddReloc(r.group(2), r.group(4), r.group(5), r.group(7), r.group(8))
                else:
                    self.__SkipLine(line)
            else:
                self.__SkipLine(line)

    def __SkipLine(self, line):
        if re.match(r'^[ -]*$', line): return
        if re.match(r'\s*#\s+Offset\s+Relocation\s+Addend\s+Symbol\s+Section', line): return
        if re.match(r'^Errors|Warnings: none', line): return
        log('SKIP:', '>' + line + '<')


class ElfFileParser(ElfContentParser):

    def __init__(self, libname, libfilename):
        self.libfilename = libfilename
        if storehex:
            process = subprocess.run([stm8tool_ielfdump, r"--no_header", r"--all", libfilename], text=True,
                                     capture_output=True)
        else:
            process = subprocess.run([stm8tool_ielfdump, r"--no_header", r"--code", libfilename], text=True,
                                     capture_output=True)
        ElfContentParser.__init__(self, libname, process.stdout)

    def _Get_TitleLog(self):
        return r'Processing lib {} {}'.format(self.libname, self.libfilename)


class ArcUnpacker:

    def __init__(self, arcfilename, dir):
        log(r'Processing arc file:', arcfilename)
        self.pat = []
        curdir = os.getcwd()
        if storearchive:
            tmpdir = None
            if os.path.exists(dir):
                print('[*] Folder "{}" already exists. If you want to recreate, then remove first'.format(dir))
                self.pat = None
                return
                # shutil.rmtree(dir)
            os.mkdir(dir)
        else:
            tmpdir = tempfile.TemporaryDirectory()
            dir = tmpdir.name
        os.chdir(dir)
        subprocess.run([stm8tool_iarchive, r"--extract", curdir + r'/' + arcfilename])  # todo: fix abs+abs path
        alist = os.listdir(r'./')
        try:
            for ofile in alist:
                libname = os.path.splitext(ofile)[0]
                self.pat.extend(ElfFileParser(libname, ofile).pat)
        finally:
            os.chdir(curdir)
        if tmpdir:
            tmpdir.cleanup()


def BuildPat(libfilename):
    basenamefull, fileext = os.path.splitext(libfilename)
    libname = os.path.split(basenamefull)[1]

    if fileext == '.txt':
        # lib dump -> pat
        basenamefull = os.path.splitext(basenamefull)[0]
        libname = os.path.split(basenamefull)[1]

        with open(libfilename, "r") as file:
            content = file.read()
            file.close()
        pat = ElfContentParser(libname, content).pat

    elif fileext == '.o':
        # lib -> pat
        pat = ElfFileParser(libname, libfilename).pat

    elif fileext == '.a':
        # archive -> pat
        pat = ArcUnpacker(libfilename, libname).pat

    elif fileext == '.pat':
        pat = None

    else:
        print(r'Not a .a or .o or .txt or .pat file')
        return

    if not pat and pat is not None == 0:
        print(r'No signatures found')
        return

    patname = basenamefull + '.pat'
    if pat:
        patfile = open(patname, "w")
        try:
            patfile.write('\n'.join(pat))
            patfile.write('\n---\n')
        finally:
            patfile.close()

    if os.path.isfile(patname):
        # pat -> sig
        signame = basenamefull + '.sig'
        if not subprocess.run([idatool_sigmake, r'-nIAR lib ' + libfilename, patname, signame]).returncode:
            print(r'Put the', signame, r'file in the folder IDAPro\sig\st8')
        else:
            print(r'Please check the .exc and .err files')
    else:
        print(r'{} file is missing'.format(patname))


assert sys.version_info >= (3, 6), r'dict should be ordered'
if __name__ == "__main__":
    if len(sys.argv) >= 2:
        BuildPat(sys.argv[1])
    else:
        print("Convert IAR STM8 Lib file to IDA Pro FLIRT signatures")
        print("Usage:")
        for v in [r"archive.a", r"elf.o", r"elf.o.txt", r"pattern.pat"]:
            print(sys.argv[0], v)
