#!/usr/bin/python3

import os
import sys
import argparse
import re
import itertools
from multiprocessing import Pool, cpu_count
import subprocess
import re

#PREFIX = os.environ['STATIC_ANALYSIS_KERNEL_DIR']

PREFIX = '/home/jiakai/tmp/linux'

memory_locations = {}

def remove_column(text):
    toks = text.split(':')
    toks[2] = '0'
    return ':'.join(toks)

def strip_start(text, prefix):
    if not text.startswith(prefix):
        return text
    ret = text[-(len(text) - len(prefix)):]
    if ret.startswith("./"):
        return ret[2:]
    return ret

def get_line(filepath, lineno):
    result = subprocess.run(
        ["sed", "-n", f"{lineno}p", filepath],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8'
    )
    if result.returncode == 0:
        return result.stdout.rstrip('\n')
    else:
        return None

def in_same_subsystem(src1, src2):
    # 默认是比较一级子目录及以下的路径
    top_level_subsystems = ['virt', 'samples', 'lib', 'include', 'fs', 'kernel', 'mm', 'init', 'drivers', 'sound', 'block', 'io_uring', 'net', 'crypto', 'security', 'usr', 'scripts', 'ipc', 'rust', 'certs', 'arch', 'tools']
    if src1[0] == '/':
        src1 = src1[1:]
    if src2[0] == '/':
        src2 = src2[1:]
    src1_split = src1.split('/')
    src2_split = src2.split('/')
    level = 0
    while level < len(src1_split) and level < len(src2_split):
        if src1_split[level] != src2_split[level]:
            break
        level += 1
    return level

class Instruction:
    def __init__(self):
        self.load_from = set()
        self.store_to = set()
        self.source_loc = None
        self.pointer_type = None
        self.line = ''
        # 该指令隶属的函数（如果是内联，就是指内联的函数）
        self.function = None
        # 该指令隶属配置项（有可能一个指令隶属多个配置项，先记录第一个）
        self.config = None
        self.src = None
        self.line = None

    def is_integer(self):
        return self.pointer_type in ['i8', 'i16', 'i32', 'i64']

    def is_general_pointer(self):
        return self.pointer_type in ['i8*', 'i16*', 'i32*', 'i64*']

    def extract_type(self, line):
        if not self.is_write:
            load_pos = line.find('load ')
            rest = line[load_pos + len('load ') : ]
            if load_pos == -1:
                return False
        else:
            store_pos = line.find('store ')
            rest = line[store_pos + len('store ') : ]
            if store_pos == -1:
                return False
        is_function_pointer = False
        idx = 0
        for i in range(len(rest)):
            if rest[i] == ',':
                # 可能到头了，所以要检查一下
                # 如果栈是空的，那就确实是提取完了
                if idx == 0:
                    self.pointer_type = rest[ : i]
                    break
            if rest[i] == '(':
                idx += 1
                is_function_pointer = True
            elif rest[i] == ')':
                idx -= 1
        # print(rest)
        if self.pointer_type.startswith('%'):
            self.pointer_type = self.pointer_type[1 : ]
        if len(self.pointer_type.split(' ')) > 1 and not is_function_pointer:
            self.pointer_type = self.pointer_type.split(' ')[0]
        return True

    def __parse_pts(line):
        line = line.strip()
        line = line[line.index("{") + 1 : len(line) - 1]
        return set(map(int, line.split()))

    def feed_line(self, line, is_write):
        pts = Instruction.__parse_pts(line)
        self.is_write = is_write
        if is_write:
            self.store_to |= pts
        else:
            self.load_from |= pts

    def get_accessed_memory_location(self):
        return list(zip(self.store_to, [True]*len(self.store_to))) + \
                list(zip(self.load_from, [False]*len(self.load_from)))

    def get_source_location(self):
        return remove_column(strip_start(self.source_loc, PREFIX))

    def get_pointer_type(self):
        return self.pointer_type
    
    def is_branch_inst(self):
        patterns = ['if (', 'if(', 'for(', 'for (', 'while(', 'while (', 'switch ', 'case ']
        src = self.src
        if self.src.startswith('linux'):
            src = PREFIX + src[5:]
        else:
            src = PREFIX + '/' + src
        result = subprocess.run(
            ["sed", "-n", f"{self.line}p", src],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8'
        )
        if result.returncode == 0:
            line = result.stdout.rstrip('\n')
            for pattern in patterns:
                if pattern in line:
                    return True
            return False
        else:
            # 找不到，默认False
            # print("好吧其实是我没找到")
            return False

class MemoryLocation:
    def __init__(self, id):
        self.id = id
        self.load_insn = set()
        self.store_insn = set()

    def add_instruction(self, insn, is_write):
        source_loc = insn.get_source_location()
        if is_write:
            self.store_insn.add(insn)
        else:
            self.load_insn.add(insn)
        # print("Load:", self.load_insn)
        # print("Store:", self.store_insn)

    def generate_result(self):
        if aset:
            return self.__generate_aliased_set()
            # return self.__generate_aliased_set_by_config()
        else:
            # return self.__generate_mempair()
            return self.__generate_mempair_by_config()

    def __generate_aliased_set(self):
        return self.id, \
                list(self.load_insn) + list(self.store_insn), \
                ['R']*len(self.load_insn) + ['W']*len(self.store_insn)

    def __generate_mempair(self):
        st_st = list(itertools.product(self.store_insn, self.store_insn))
        st_ld = list(itertools.product(self.store_insn, self.load_insn))
        return self.id, \
                (st_st + st_ld), \
                [('W', 'W')]*len(st_st) + [('W', 'R')]*len(st_ld)

    def __generate_mempair_by_config(self):
        # 升级版，先看读写语句（不看写写语句）是否在同一/相关配置项内，只有在才保留
        # （注意！！！）这里可能有一个待尝试的方向，闲暇时间可以试试：
        # 我们都知道，影响一条路径是否被执行的因素，是这条路径上的条件分支语句是否都被正确地执行了，
        # 而条件分支判断语句，其本质也是一条读语句，
        # 因此，对条件分支判断语句进行基于配置项的写语句匹配可能比一般的读语句匹配更有价值，这样生成的syscall关系图也不会过于稠密。
        # 因此在遍历load_insn时可以加一条判断：如果读语句不是条件分支判断语句，那就跳过，不对它进行匹配。
        # load_insn的source_loc属性存储了该语句对应的源码，可以用这个判断？或者其他方法也可以？
        st_ld = []
        config_load, config_store = None, None
        # print(len(self.load_insn), ':', len(self.store_insn))
        for load_insn in self.load_insn:
            # 必须是分支指令的依赖才有意义
            if not load_insn.is_branch_inst():
                continue

            config_load = load_insn.config

            for store_insn in self.store_insn:
                config_store = store_insn.config
                # print("STORE src: ", store_insn.src, " line: ", store_insn.line, " config_store: ", config_store)

                if config_load is None or config_store is None:
                    continue

                if config2code.are_related_configs(config_load, config_store):
                    # print("Found!")
                    # print("LOAD src: ", load_insn.source_loc, "STORE src: ", store_insn.source_loc, "config: ", config_load)
                    st_ld.append((load_insn.src, load_insn.line, store_insn.src, store_insn.line))
                    # st_ld.append((store_insn.source_loc, load_insn.source_loc))
                else:
                    # 默认最低等级，即同一源码文件
                    if store_insn.src == load_insn.src:
                    # if in_same_subsystem(load_insn.src, store_insn.src):
                        # print("Found!")
                        # print("LOAD src: ", load_insn.source_loc, "STORE src: ", store_insn.source_loc, "config: ", config_load)
                        st_ld.append((load_insn.src, load_insn.line, store_insn.src, store_insn.line))
                        # st_ld.append((store_insn.source_loc, load_insn.source_loc))

                        # new_config = config2code.process_possibly_incorrect_configs(store_insn, load_insn)
                        # if new_config != None:
                        #     store_insn.config.add(new_config)
        
        return self.id, \
                st_ld, \
                [('W', 'R')]*len(st_ld)

class MempairResult:
    def __init__(self):
        self.deduped_mempair = {}

    def __sort(mempair, typ):
        if mempair[0] > mempair[1]:
            return (mempair[1], mempair[0]), (typ[1], typ[0])
        return mempair, typ

    def add(self, locid, mempairs, types):
        # mempairs每一项的结构是：
        # load_insn.src, load_insn.line, store_insn.src, store_insn.line
        for mempair,typ in zip(mempairs, types):
            # sorted_mempair, sorted_typ = MempairResult.__sort(mempair, typ)
            # self.deduped_mempair[sorted_mempair] = sorted_typ
            self.deduped_mempair[mempair] = typ

    def print_all(self):
        for mempair in self.deduped_mempair.keys():
            for mempair, typ in sorted(self.deduped_mempair.items()):
                print(mempair[0], mempair[1], mempair[2], mempair[3])

class AliasedSetResult:
    def __init__(self):
        self.aliased_set_per_memloc = {}

    class AliasedSet:
        def __init__(self, aliased_set, typ):
            self.set = set()
            for source_loc, typ in zip(aliased_set, types):
                self.set.add((source_loc, typ))

        def __iter__(self):
            return self.set.__iter__()

    def __is_subset(self, sub_memlocid, super_memlocid):
        for insn in self.aliased_set_per_memloc[sub_memlocid]:
            if not insn in self.aliased_set_per_memloc[super_memlocid]:
                return False
        return True

    def __remove_duplicate(self, memlocid):
        for other_memlocid in list(self.aliased_set_per_memloc):
            if other_memlocid != memlocid and self.__is_subset(memlocid, other_memlocid):
                del self.aliased_set_per_memloc[memlocid]
                return
        for other_memlocid in list(self.aliased_set_per_memloc):
            if other_memlocid != memlocid and self.__is_subset(other_memlocid, memlocid):
                del self.aliased_set_per_memloc[other_memlocid]

    def add(self, memlocid, aliased_set, types):
        if len(aliased_set) == 1:
            return
        self.aliased_set_per_memloc[memlocid] = AliasedSetResult.AliasedSet(aliased_set, types)
        self.__remove_duplicate(memlocid)

    def print_all(self):
        for memlocid, aliased_set in sorted(self.aliased_set_per_memloc.items()):
            print("[Memory location ID: %d]" % memlocid[0])
            for insn in sorted(aliased_set, key = lambda x: (x[1], x[0])):
                print("\tType: ", insn[1], "\t", insn[0])

def extract_src_and_line(source_loc):
    # 默认是返回从一级子目录以下的内容
    # print(source_loc)
    src_pattern = r'fl:\s[a-zA-z0-9\_\/\.]+'
    line_pattern = r'ln:\s[0-9]+'
    src = re.findall(src_pattern, source_loc)[0][4:]
    line = int(re.findall(line_pattern, source_loc)[0][4:])
    if src.startswith('linux/'):
        src = src[6:]
    return src, line

def inst_process(insn, memory_locations):
    src, line = extract_src_and_line(insn.source_loc)
    # 默认是返回从一级子目录以下的内容
    insn.src = src
    insn.line = line
    # print(src, ':', line)
    # config = config2code.code2config(src, int(line))
    # print(config)
    # insn.config = config

    # if insn.is_integer() or insn.is_general_pointer():
    #     continue

    typ = insn.get_pointer_type()
    # print(typ)
    for memloc, is_write in insn.get_accessed_memory_location():
        if memloc == 1:
            continue
        key = (memloc, typ)
        # print("Memory location:", key, " in ", insn.function, " at ", insn.src, ":", insn.line, " type: ", typ, " is_write: ", is_write)
        if not key in memory_locations:
            memory_locations[key] = MemoryLocation(key)
        memory_locations[key].add_instruction(insn, is_write)
        
    return memory_locations

def memory_compare(result):
    for key in memory_locations:
        locid, results, types = memory_locations[key].generate_result()
        # print("locid: ", locid, "results: ", results, " types: ", types)
        result.add(locid, results, types)
    return result

def find_source_with_type(i, mssa_lines, is_write):
    p = -1
    typ = None
    
    load_pat = ' load '
    memcpy_pat = '@llvm.memcpy.'

    store_pat = ' store '
    alloca_pat = ' alloca '
    bitcast_pat = ' bitcast '
    if not is_write:
        # 在LDMU的后面
        # 然而有load但不一定有源码信息，如果没有则意味着多行IR对应一行源码
        # 就继续往下找直至找到有源码的那一行为止
        # 反正我们获取source_loc只是为了源码信息，IR究竟是什么无所谓
        # 注：因为有多个LDMU挤在一起，所以不一定找得到
        k = i + 1
        p = k
        while k < len(mssa_lines):
            line = mssa_lines[k]
            if ' ln: ' in line:
                p = k
                break
            k += 1
        line = mssa_lines[k]
        load_pos = line.find(load_pat)
        if load_pos != -1:
            rest = line[load_pos + len(load_pat) : ]
        else:
            # 像llvm.memcpy这种过于复杂的暂时处理不了
            return -1, None
    else:
        # 在STCHI的前面
        # 注：因为有多个STCHI挤在一起，所以不一定找得到
        k = i - 1
        can_parse_type = False
        while k >= 0:
            line = mssa_lines[k]
            if " = STCHI(" in line:
                k -= 1
                continue
            if bitcast_pat in line:
                can_parse_type = True
                store_pos = line.find(bitcast_pat)
                rest = line[store_pos + len(bitcast_pat) : ]
            elif alloca_pat in line:
                can_parse_type = True
                store_pos = line.find(alloca_pat)
                rest = line[store_pos + len(alloca_pat) : ]
            elif store_pat in line:
                can_parse_type = True
                store_pos = line.find(store_pat)
                rest = line[store_pos + len(store_pat) : ]
            
            if can_parse_type and ' ln: ' in line:
                p = k
                break
            else:
                k -= 1
    
    if k == -1:
        return -1, None

    is_function_pointer = False
    idx = 0
    typ = rest.strip()
    for i in range(len(rest)):
        if rest[i] == ',':
            # 可能到头了，所以要检查一下
            # 如果栈是空的，那就确实是提取完了
            if idx == 0:
                typ = rest[ : i]
                break
        if rest[i] == '(':
            idx += 1
            is_function_pointer = True
        elif rest[i] == ')':
            idx -= 1
    # print('rest:', rest)
    if typ.startswith('%'):
        typ = typ[1 : ]
    if len(typ.split(' ')) > 1 and not is_function_pointer:
        typ = typ.split(' ')[0]
    return p, typ


def analyze_bcs(bcs):
    current_function = None
    memory_locations = {}
    
    try:
        mssa_file = open(bcs, 'r')
    except:
        print(f"[ERROR] File not found: {bcs}")
        return memory_locations

    mssa_lines = mssa_file.readlines()
    for i in range(len(mssa_lines)):
        line = mssa_lines[i]
        if len(line.strip()) == 0:
            continue
        if "LDMU" in line or "STCHI" in line:
            insn = Instruction()
            insn.line = line.strip()
            insn.function = current_function
            current_function = None
            if "LDMU" in line:
                insn.feed_line(line, is_write = False)
                k, typ = find_source_with_type(i, mssa_lines, False)
                if k == -1 and typ == None:
                    # 这条指令过于复杂处理不了，跳过
                    continue
                insn.source_loc = mssa_lines[k]
                insn.pointer_type = typ
                memory_locations = inst_process(insn, memory_locations)
            elif "STCHI" in line:
                insn.feed_line(line, is_write = True)
                k, typ = find_source_with_type(i, mssa_lines, True)
                if k == -1 and typ == None:
                    # 这条指令过于复杂处理不了，跳过
                    continue
                insn.source_loc = mssa_lines[k]
                insn.pointer_type = typ
                # insn.extract_type(insn.source_loc)
                memory_locations = inst_process(insn, memory_locations)
            # insts.append(insn)
        elif "FUNCTION:" in line:
            current_function = line.strip().split("==========FUNCTION:")[1].split("==========")[0].strip()

        # 处理生成结果
        # result = memory_compare(result)
    return memory_locations