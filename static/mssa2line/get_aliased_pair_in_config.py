#!/usr/bin/python3

import os
import sys
import argparse
import re
import itertools
from multiprocessing import Pool, cpu_count
import re

from config2code import Config2Code

'''
/root/razzer/tools/race-syzkaller/exp/configs/kernel/partition/v4.17/mssa.kernel-time
Total instructions: 20941
Total load instructions: 13970/5926
Total store instructions: 6971

mssa.driver-net-phy
Total instructions: 27809
Total load instructions: 18802/6888
Total store instructions: 9007
'''

#PREFIX = os.environ['STATIC_ANALYSIS_KERNEL_DIR']

PREFIX = '/home/jiakai/tmp/linux'
parser = argparse.ArgumentParser(description='Get aliased pair from the SVF result.')
parser.add_argument('mssa')
parser.add_argument('--aset', dest='aset', action='store_true')

parser.add_argument('--config_codeblock_path', dest='config_codeblock_path', default=None,
                    help='Path to the config codeblock file, used to get the related configs.')
parser.add_argument('--config_tree_path', dest='config_tree_path', default=None)

args = parser.parse_args()

mssa = args.mssa
aset = args.aset

config_codeblock_path = args.config_codeblock_path
config_tree_path = args.config_tree_path

config2code = Config2Code(config_codeblock_path, config_tree_path)

memory_locations = {}
load_insn, store_insn = 0, 0

def remove_column(text):
    if aset:
        return text
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

    def is_integer(self):
        return self.pointer_type in ['i8', 'i16', 'i32', 'i64']

    def is_general_pointer(self):
        return self.pointer_type in ['i8*', 'i16*', 'i32*', 'i64*']

    def extract_type(self, line):
        typ = line[line.find("({") + 2 : line.find("})")]
        for regex in re.findall('struct\.[^\ ]*\.[0-9]+[^\ \*]*', typ):
            newregex = re.sub(r'\.[0-9]+$', '', regex)
            typ = typ.replace(regex, newregex)
        for regex in re.findall('\.[0-9]+:', typ):
            newregex = re.sub(r'\.[0-9]+:', ':', regex)
            typ = typ.replace(regex, newregex)
        self.pointer_type = typ

    def extract_source_location(self, line):
        # loc = line.strip().split("[[")[1]
        # if loc.find("@[") != -1:
        #     # It is inlined at somewhere, but I don't care where it is inlined at
        #     delim = "@["
        # else:
        #     # No inlined
        #     delim = "]]"
        # self.source_loc = loc.split(delim)[0].strip()

        loc = line.strip().split("[[")[1]
        matches = re.findall(r'([^\s\[\]@]+:\d+:\d+)', loc)
        if matches:
            self.source_loc = matches[-1]

    def __parse_pts(line):
        line = line.strip()
        line = line[line.index("{") + 1 : len(line) - 1]
        return set(map(int, line.split()))

    def feed_line(self, line, is_write):
        pts = Instruction.__parse_pts(line)
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
        for load_insn in self.load_insn:
            found = False
            config_load = load_insn.config

            for store_insn in self.store_insn:
                config_store = store_insn.config
                # print("STORE src: ", src2, " line: ", line2, " config_store: ", config_store)

                if config_load is None or config_store is None:
                    continue
                # 第一层，最严格的，两个配置项必须完全相同
                #if config_load & config_store:
                # 第二层，两个配置项为相关配置项
                if config2code.are_related_configs(config_load, config_store):
                    print("Found!")
                    print("LOAD src: ", load_insn.source_loc, "STORE src: ", store_insn.source_loc, "config: ", config_load)
                    st_ld.append((store_insn.source_loc, load_insn.source_loc))
        
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
        for mempair,typ in zip(mempairs, types):
            sorted_mempair, sorted_typ = MempairResult.__sort(mempair, typ)
            self.deduped_mempair[sorted_mempair] = sorted_typ

    def print_all(self):
        for mempair, typ in sorted(self.deduped_mempair.items()):
            print(mempair[0], mempair[1], typ[0], typ[1])

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

def inst_process(insn):
    global load_insn
    global store_insn
    source_locs = []

    # set a source location
    insn.extract_source_location(insn.line)
    # set a type of the pointer
    insn.extract_type(insn.line)

    src = insn.source_loc.split(':')[0]
    line = insn.source_loc.split(':')[1]
    # print(src, ':', line)
    config = config2code.code2config(src, int(line))
    # print(config)
    insn.config = config

    # if insn.is_integer() or insn.is_general_pointer():
    #     continue

    typ = insn.get_pointer_type()
    for memloc, is_write in insn.get_accessed_memory_location():
        if memloc == 1:
            continue
        key = (memloc, typ)
        if not key in memory_locations:
            memory_locations[key] = MemoryLocation(key)
        memory_locations[key].add_instruction(insn, is_write)
    
        if insn.source_loc not in source_locs:
            source_locs.append(insn.source_loc)
            if is_write:
                store_insn += 1
            else:
                load_insn += 1
    
    del source_locs
        
    return insn

def memory_compare(result):
    for key in memory_locations:
        locid, results, types = memory_locations[key].generate_result()
        # print("locid: ", locid, "results: ", results, " types: ", types)
        result.add(locid, results, types)
    return result

if __name__ == '__main__':
    insts = []
    
    current_function = None
    with open(mssa, 'r') as mssa_file:
        reset = True

        for line in mssa_file:
            if len(line.strip()) == 0:
                continue
            if reset:
                reset = False
                insn = Instruction()

            if "LDMU" in line:
                insn.feed_line(line, is_write= False)
                print("Found LDMU instruction.")
            elif "STCHI" in line:
                insn.feed_line(line, is_write= True)
                print("Found STCHI instruction.")
            elif "FUNCTION:" in line:
                current_function = line.strip().split("==========FUNCTION:")[1].split("==========")[0].strip()
            elif "[[" in line:
                reset = True
                insn.line = line.strip()
                insn.function = current_function
                current_function = None
                insts.append(insn)

    if aset:
        result = AliasedSetResult()
    else:
        result = MempairResult()

    # # 并发处理insts
    # with Pool(cpu_count()) as pool:
    #     insts = pool.map(inst_process, insts)

    for i in range(len(insts)):
        # print(i)
        insts[i] = inst_process(insts[i])

    print("Instructions processing completed. ", str(len(memory_locations)))
    print("Total instructions:", load_insn + store_insn)
    print("Total load instructions:", load_insn)
    print("Total store instructions:", store_insn)

    # 处理生成结果
    result = memory_compare(result)
    
    # 现在还是无格式输出，建议按某种格式存入文件，以方便后面解析
    output_path = "result_related2.txt"
    with open(output_path, 'w+') as f:
        sys.stdout = f
        result.print_all()
        sys.stdout = sys.__stdout__
    print("Results are written to", output_path)
