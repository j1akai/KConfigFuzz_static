import os
import json
from config2code import Config2Code
from mempair import MemoryLocation, Instruction, analyze_bcs
from copy import deepcopy

MSSA_PATH = "/home/jiakai/KConfigFuzz/static/bc2mssa/output"

bcs_index = None
index_config = None
config2code = None
# 这个该是全局变量还是局部变量（搜一个新创建一个）？
dep_pairs = set()

class Queue():
    def __init__(self):
        self.items = []
        self.categories = set()
    def put(self, item):
        if item not in self.categories:
            self.items.append(item)
            self.categories.add(item)
    def get(self):
        if not self.empty():
            item = self.items.pop(0)
            self.categories.remove(item)
            return item
        return None
    def empty(self):
        return len(self.items) == 0

def read(src):
    with open(src, 'r') as f:
        return json.load(f)

def aggregate(index_config):
    configs = set()
    for k, v in index_config.items():
        for config in v:
            if config not in configs:
                configs.add(config)
    return configs

def merge(ans):
    for dep_pair in ans:
        if type(dep_pair[0]) != Instruction or type(dep_pair[1]) != Instruction:
            continue
        dep_pairs.add(dep_pair)

def get_bcs(config):
    # 先从index_config中找到config对应的映射
    for index, configs in index_config.items():
        if config in configs:
            # 再返回对应的合并版bcs路径
            return os.path.join(MSSA_PATH, "mssa."+index)

def get_near_pair(read_inst):
    read_inst_src = read_inst.src
    read_inst_line = read_inst.line
    final_pair = None
    for pair in dep_pairs:
        candidate_read, candidate_write = pair[0], pair[1]
        if type(candidate_read) != Instruction or type(candidate_write) != Instruction:
            continue
        if candidate_read.src == read_inst_src:
            if final_pair == None or \
                abs(final_pair[0].line - read_inst_line) > \
                abs(candidate_read.line - read_inst_line):
                # print("这个依赖对更近：{}".format(pair))
                final_pair = pair
    return final_pair

# 根据src找到包含src且最小的合并版bitcode代码块
def get_minimal_bcs(src):
    # 先使用os库把src的后缀统一转换成.bc
    if not src.endswith(".bc"):
        src = src.rsplit('.', 1)[0] + ".bc"
    final_bcs_src = None
    min_size = float('inf')
    for index, bcs in bcs_index.items():
        if src in bcs:
            possible_src = os.path.join(MSSA_PATH, "mssa."+index)
            if not os.path.exists(possible_src):
                continue
            # 获取文件大小
            size = os.path.getsize(possible_src)
            if size < min_size:
                min_size = size
                final_bcs_src = possible_src
                # print("当前找到更小的合并版bcs：{}，大小为{}".format(possible_src, size))
    # print("最终找到的最小合并版bcs为：{}".format(final_bcs_src))
    return final_bcs_src


# 同一个配置项的分析
# 都要
def same_config_analysis(read_inst, write_insts_for_analysis):
    ans = []
    for write_inst in write_insts_for_analysis:
        ans.append((read_inst, write_inst))
    return ans

# 相关配置项的分析
def in_config_analysis(read_inst, read_configs, var, write_insts_for_analysis, p, ans):
    while not p.empty():
        c = p.get()
        # print("当前配置项{}出列。".format(c))
        # 配置项管辖的代码所在的源码文件的集合，这里可能还涵盖了一些不被源码包裹的其它源码
        bcs = get_bcs(c)
        # print("当前配置项{}对应的合并版bcs路径为{}。".format(c, bcs))
        if bcs == None:
            continue
        # 把源码文件里所有的读写指令都分析出来
        # 指令是analysis里的Instruction类，包括类型，地址，源码行号和所属配置项等信息
        mempairs = analyze_bcs(bcs)
        # print(mempairs)
        write_insts_for_analysis = [inst for inst in mempairs.get(var, MemoryLocation(0)).store_insn]
        for write_inst in write_insts_for_analysis:
            ans.append((read_inst, write_inst))
    return ans

# 配置项外的分析
def out_config_analysis(read_inst, write_insts, var, ans):
    write_lists = [[0], [0]]
    # 在附近找到一个被配置项管辖且已找到的依赖对
    # 读指令要在待搜索读指令的附近
    dep_pair = get_near_pair(read_inst)
    # print("在配置项外找到的依赖对为：{}".format(dep_pair))
    if dep_pair == None:
        # print("不行。由于搜索太早或者位置过于特殊，没有在该读指令附近找到已知依赖对，放弃在配置项外搜索。")
        return ans
    # print("在附近找到依赖对了：{}".format(dep_pair))
    # 在这依赖对附近找依赖
    dep_read_inst, dep_write_inst = dep_pair[0], dep_pair[1]
    # 先在写指令附近找
    write_src = dep_write_inst.src
    minimal_bcs = get_minimal_bcs(write_src)
    mempairs = analyze_bcs(minimal_bcs)
    write_insts = [write_inst for write_inst in mempairs.get(var, MemoryLocation(0)).store_insn]
    write_lists[0] = write_insts
    # 再在读指令附近找
    read_src = dep_read_inst.src
    minimal_bcs = get_minimal_bcs(read_src)
    mempairs = analyze_bcs(minimal_bcs)
    write_insts = [write_inst for write_inst in mempairs.get(var, MemoryLocation(0)).store_insn]
    write_lists[0] = write_insts
    for write_list in write_lists:
        for write_inst in write_list:
            # if has_relationships(read_configs, write_configs):
            #     ans.append((read_inst, write_inst))
            ans.append((read_inst, write_inst))

    # （待考虑）找到后，如果它被配置项管辖则考虑修复配置项关系

    return ans

# 分析主流程
def analysis(config):
    # 初始化队列
    q = Queue()
    # 当前配置项入队
    q.put(config)
    # print("当前配置项{}入队。".format(config))
    # 配置项的子配置项入队（需要config2code模块的协助，下同）
    for child in config2code.get_child_configs(config):
        q.put(child)
        # print("当前子配置项{}入队。".format(child))
    # 配置项的父配置项入队
    for parent in config2code.get_parent_configs(config):
        q.put(parent)
        # print("当前父配置项{}入队。".format(parent))
    # 获取所有待分析的读指令集合
    bcs_src = get_bcs(config)
    # print("当前配置项{}对应的合并版bcs路径为{}。".format(config, bcs_src))
    mempairs = analyze_bcs(bcs_src)
    # print("{}对应文件的读写语句分析已完成，共计{}个可能的地址。".format(bcs_src, len(mempairs)))
    # 获取读取同一地址的写指令集合
    for var, insts in mempairs.items():
        # print("当前地址{}对应的读写指令共计{}条。".format(var, len(insts.load_insn) + len(insts.store_insn)))
        
        p = deepcopy(q)
        # print("原配置项队列重生。")
        
        # 必须是分支指令的依赖才有意义
        read_insts = [inst for inst in insts.load_insn if inst.is_branch_inst()]
        write_insts_for_analysis = [inst for inst in insts.store_insn]

        # 本配置项出列
        _ = p.get()
        # print("自身配置项{}出列。".format(config))

        for read_inst in read_insts:
            ans = None
            # 1、先分析当前配置项本身所在的源码，这个逻辑和其它配置项不太一样
            ans = same_config_analysis(read_inst, write_insts_for_analysis)
            merge(ans)
            # print("第一步后分析得到的结果：{}".format(len(ans)))

            # 2、然后再分析其他配置项所管辖的代码
            # 这个read_configs列表从开始到后面，管辖的配置项范围越来越大
            read_configs = config2code.code2config(read_inst.src, read_inst.line)
            if read_configs == None:
                # 如果读指令不被任何配置项管辖，则在配置项外搜索
                # print("这个读指令不被任何配置项管辖，开始在配置项外搜索。")
                ans = out_config_analysis(read_inst, None, var, ans)
                merge(ans)
            else:        
                # 开始分析
                # print("这个读指令被配置项{}管辖，开始在相关配置项中搜索。".format(read_configs))
                ans = in_config_analysis(read_inst, 
                                         read_configs,
                                         var, 
                                         write_insts_for_analysis,
                                         p,
                                         ans)
                merge(ans)
            # 如果还没找到，就在配置项外搜索
            if ans == None:
                # print("还没找到依赖对，开始在配置项外搜索。")
                ans = out_config_analysis(read_inst, write_insts, var, ans)
                merge(ans)

if __name__ == '__main__':
    # 先读必要的文件
    bcs_index_src = "/home/jiakai/KConfigFuzz/static/bc2mssa/bcs_index.json"
    index_config_src = "/home/jiakai/KConfigFuzz/static/bc2mssa/index_config.json"
    config_codeblock_src = "/home/jiakai/KConfigFuzz/config/config_codeblock.json"
    config_tree_src = "/home/jiakai/KConfigFuzz/config/config_tree.json"
    
    bcs_index = read(bcs_index_src)
    print(f"Total {len(bcs_index)} merged bcs for analysis")
    index_config = read(index_config_src)
    print(f"Total {len(index_config)} index for analysis")
    configs = aggregate(index_config)
    print(f"Total {len(configs)} unique configs for analysis")
    
    config2code = Config2Code(config_codeblock_src, config_tree_src)
    print(f"Total {len(config2code.config_codeblock)} configs in config2code for analysis")
    
    i = 1
    for config in configs:
        print("开始分析配置项{} {}/{}。".format(config, i, len(configs)))
        analysis(config)
        print("当前已找到的依赖对共计{}个。".format(len(dep_pairs)))
        i += 1

    with open("new_dependent_ops.txt", 'w+') as f:
        for pair in dep_pairs:
            read_inst, write_inst = pair[0], pair[1]
            f.write("{}:{}:{}:{}\n".format(write_inst.src, write_inst.line, read_inst.src, read_inst.line))
