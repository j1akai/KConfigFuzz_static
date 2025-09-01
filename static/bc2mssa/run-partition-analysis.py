#!/usr/bin/env python3
from __future__ import print_function

import os
import sys
import yaml

from perform_analysis import analyze

# 这个大小可能有问题，建议改一下
MAX_SIZE = 3*1024*1024 # 3MB
NUM_PROC = 16

#kernel_build_dir = "/home/jiakai/KConfigFuzz/workdir/linux_bc"
#kernel_build_dir = "/home/jiakai/tmp/linux_bc_O1/"
kernel_build_dir = "/home/jiakai/tmp/linux_bc_test"

def load_lst(fn):
    builtins = []
    fstr = open(fn).read()

    for line in fstr.split("\n"):
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        bc, size = line.split("\t\t")
        assert(bc.endswith(".bc"))
        builtins.append([bc])
    return builtins

def get_filesize_sum(fns):
    size = 0
    for fn in fns:
        size += os.path.getsize(fn)
    return size

def get_kver():
    kver = os.environ['KERNEL_VERSION'].strip()
    if kver == "" or not kver.startswith("v"):
        print("[ERR] Incorrect kernel version (%s)" % kver)
        sys.exit(-1)
    return kver

def recursive_collect_all_bcs(kernel_build_dir):
    import fnmatch
    import os

    matches = []
    for root, dirnames, filenames in os.walk(kernel_build_dir):
        for filename in fnmatch.filter(filenames, "*.bc"):
            matches.append(os.path.join(root, filename))
    return matches

def get_readable_size(size):
    postfixes = ["B", "K", "M", "G"]

    for postfix in postfixes:
        if size < 1024:
            return "%d%s" % (size, postfix)
        size = size/1024
    return "NA"

class DirTreeNode:
    def __init__(self, dname, path, depth):
        self.dname = dname
        self.path = os.path.join(path, dname)
        self.bcs = []
        self.child_nodes = []
        self.parent_node = None
        self.depth = depth
        self.builtin_size = -1
        self.non_builtin_size = -1
        self.child_size = -1

    def add_bc(self, bc):
        self.bcs.append(bc)

    def get_builtin_bc(self):
        if not "built-in.bc" in self.bcs:
            return None
        return os.path.join(self.path, "built-in.bc")

    def get_non_builtin_bcs(self):
        return [os.path.join(self.path, x) for x in self.bcs if x != "built-in.bc"]

    def get_opt2_size(self):
        return self.builtin_size

    def get_opt2_bcs(self):
        return [self.get_builtin_bc()]

    def get_opt1_size(self):
        # TODO: Fix opt1 size, not important
        # 即“父节点的非 built-in.bc 文件 + 当前节点的 built-in.bc 文件”的总大小。
        if self.parent_node and self.parent_node.non_builtin_size != -1:
            if self.builtin_size != -1:
                return self.parent_node.non_builtin_size + self.builtin_size
        return -1

    def get_opt1_bcs(self):
        pnode = self.parent_node
        if pnode == None:
            return None

        pnode_non_builtin_bcs = []
        while pnode != None:
            pnode_non_builtin_bcs += (pnode.get_non_builtin_bcs())
            pnode = pnode.parent_node

        if not "built-in.bc" in self.bcs:
            return None

        bcs = [self.get_builtin_bc()]
        bcs += pnode_non_builtin_bcs
        return bcs

    def get_child_node_by_dname(self, dname):
        matches = [x for x in self.child_nodes if x.dname == dname]

        assert(len(matches) == 1 or len(matches) == 0)
        if len(matches) == 1:
            return matches[0]
        return None

    def add_child_node(self, cnode):
        self.child_nodes.append(cnode)

    def set_parent_node(self, pnode):
        self.parent_node = pnode

    def __str__(self):
        s = "[%s][%d][%s] [%s]: %d childs, %d bcs" % (self.dname, self.depth, self.path,
                                                      get_readable_size(self.child_size),
                                                      len(self.child_nodes), len(self.bcs))
        return s

    def get_size_info(self, is_opt1 = True):
        if is_opt1:
            sizestr = get_readable_size(self.get_opt1_size())
        else:
            sizestr = get_readable_size(self.get_opt2_size())
        s = "[%s] %s" % (self.path, sizestr)
        return s

def change_to_match_pattern(filepath):
    dirpath = os.path.dirname(filepath)
    basename = os.path.basename(filepath)
    filename, ext = os.path.splitext(basename)
    new_basename = "%" + ext
    return os.path.join(dirpath, new_basename)

def get_child_node_by_path(node, path, depth = 0):
    # 沿着build_dir_tree构建的树结构找目标文件path对应的bitcode
    # 2：找到了该文件对应的.bc
    # （该分支已废弃，因此目前此意义与未找到无异）1：找到了该目录（或除根节点外最后一级目录），但没有找到该文件对应的.bc
    # 0：没有找到该目录

    # 若路径中有通配符%，需要特殊处理
    match_pattern = True if '%' in path else False

    # 如果找到了最后一级，那就是文件级
    if depth == len(path.split('/')) - 1:
        _, path = os.path.split(path)
        # print("1*****"+path)
        path = path.split('.')[0] + '.bc'
        # print("2*****"+path)
        path = path.split('/')[-1] # 只要最后一级的文件名
        # print("3*****"+path)
        for bc in node.bcs:
            # print("bc: " + bc + " in node: " + node.dname + " Looking for: " + path)
            if bc == path:
                # print("Found bc: " + bc + " in node: " + node.dname)
                return os.path.join(node.path, bc), 2
        # 如果没有找到最后一级，那就是目录级
        return node.path, 1

    dname = path.split('/')[depth]
    for cnode in node.child_nodes:
        # print("Looking for dname: " + dname + " in node: " + cnode.dname)
        # 如果找到了该级的目录
        if cnode.dname == dname:
            # 去该级目录下找下一级目录/文件
            bc_or_node, result = get_child_node_by_path(cnode, path, depth + 1)
            # 如果最终找到了该文件，返回
            if result == 2:
                return bc_or_node, 2
            # 如果最终找到了该目录，但没有找到该文件
            elif result == 1:
                # 如果不是根节点，返回1
                if depth >= 1:
                    return bc_or_node, 1
                # 如果是根节点，返回0，寻找失败
                else:
                    return None, 0
    # 如果该级下没有找到该目录
    if depth > 0:
        # 如果不是根节点，返回该级目录
        return node.path, 1
    else:
        # 如果是根节点，返回0，寻找失败
        return None, 0

def build_dir_tree(pnode, sub_dirs):
    dname = sub_dirs[0]

    if dname.endswith(".bc"):
        pnode.add_bc(dname)
    else:
        node = pnode.get_child_node_by_dname(dname)
        if node == None:
            node = DirTreeNode(dname, pnode.path, pnode.depth+1)
            node.set_parent_node(pnode)
            pnode.add_child_node(node)
        build_dir_tree(node, sub_dirs[1:])
    return

def auto_collect_bcs():

    print(kernel_build_dir)

    files = recursive_collect_all_bcs(kernel_build_dir)
    # print(files)
    files = [x.replace(kernel_build_dir, "") for x in set(files)]
    # print(files)
    files = sorted(files)
    # print(files)

    print(len(files))

    # Build Dir Tree
    root_node = DirTreeNode("", "", 0)
    for fn in files:
        dirs = [x for x in fn.split("/") if x != ""]
        # print(dirs)
        build_dir_tree(root_node, dirs)

    visit_to_compute_bcsize(root_node, kernel_build_dir)

    bcgroups = visit_to_collect(root_node, kernel_build_dir)

    # Ensure none of the "first" bc overlaps with others, as the first
    # bc will be used as the analysis name.
    names = []
    for bcs in bcgroups:
        name = bcs[0]
        if name in names:
            assert(False and "the first bc should not collide")
        names.append(name)

    return root_node, bcgroups


def visit_to_collect(pnode, kernel_build_dir):
    bcgroups = []
    #1 parent's non_builtin + current built-in

    handled = False
    opt1_size = pnode.get_opt1_size()
    if opt1_size != -1 and opt1_size < MAX_SIZE:
        print("[OPT1]       ", pnode.get_size_info())
        print("\t\t\t", pnode.get_opt1_bcs())

        bcgroups.append(pnode.get_opt1_bcs())
        handled = True


    if not handled:
        handled = True
        for cnode in pnode.child_nodes:
            bcs = visit_to_collect(cnode, kernel_build_dir)
            bcgroups.extend(bcs)
            if len(bcs) == 0:
                # print("threr 259")
                handled = False

        if not handled:
            #2 fallback scheme: just current built-in

            opt2_size = pnode.get_opt2_size()
            if opt2_size != -1 and opt2_size < MAX_SIZE:
                print("[OPT2]     ", pnode.get_size_info(False))
                print("\t\t\t", pnode.get_opt2_bcs())
                bcgroups.append(pnode.get_opt2_bcs())
    return bcgroups

def visit_to_compute_bcsize(pnode, kernel_build_dir):
    for cnode in pnode.child_nodes:
        visit_to_compute_bcsize(cnode, kernel_build_dir)

    # compute sum of bc files
    non_builtin_size = 0
    for bc in pnode.get_non_builtin_bcs():
        fn = os.path.join(kernel_build_dir, bc)
        non_builtin_size += os.path.getsize(fn)

    pnode.non_builtin_size = non_builtin_size
    builtin_fn = pnode.get_builtin_bc()
    if builtin_fn != None:
        pnode.builtin_size = os.path.getsize(os.path.join(kernel_build_dir, pnode.get_builtin_bc()))

    child_size = 0
    for cnode in pnode.child_nodes:
        if cnode.builtin_size != -1:
            child_size += cnode.builtin_size
        elif cnode.non_builtin_size != -1:
            child_size += cnode.non_builtin_size
        else:
            print(cnode)
            assert(False and "something wrong")
    print(pnode,"child_size = ",get_readable_size(child_size), pnode.get_opt1_size(),pnode.get_opt2_size())
    pnode.child_size = child_size
    print(pnode,"child_size = ",get_readable_size(child_size), pnode.get_opt1_size(),pnode.get_opt2_size())

def DFS(node):
    if node == None:
        return
    # print("Node dname: ", node.dname, " Node path: ", node.path)
    print(node)
    for child in node.child_nodes:
        DFS(child)

def arrange_bcs_by_config(bcgroups, root_node, config_codeblocks, src_objs):
    # 根据每个配置项所管辖的代码块，将每个配置项对应的.bc文件聚集起来
    # 如果一个配置项对应的代码块没有.bc文件，则寻找其父节点的.bc文件进行聚集
    # 最终返回一个字典，键为配置项，值为对应的.bc文件列表
    # 这个字典可能很大（取决于编译内核时打开了多少个配置项）
    # 由于不是每一个源码文件都对应一个同名的.bc文件，因此还需要src_objs将源码和.bc文件对应上
    config_bcs = {}

    for config, codeblocks in config_codeblocks.items():
        config_bcs[config] = []
        size = 0
        srcs = list(codeblocks.keys())
        config_src_objs = {}
        
        for src in srcs:
            src = src.replace("/home/jiakai/tmp/linux", "")
            if src.startswith('/'):
                src = src[1:]

            tmp = []
            if src_objs.get(src) is not None:
                tmp = src_objs[src]
            else:
                # 可能是通配符
                # 先把路径改为通配符，然后再搜索
                # （不过真的存在一个未被通配符标记的源码路径，对应一个被通配符标记的目标文件吗？那也太奇怪了吧）
                src_for_match_pattern = change_to_match_pattern(src)
                if src_objs.get(src_for_match_pattern) is not None:
                    tmp = src_objs[src_for_match_pattern]
            
            if config_src_objs.get(src) is None:
                config_src_objs[src] = tmp
            else:
                config_src_objs[src] = config_src_objs[src] + tmp
        
        for src, objs in config_src_objs.items():
            for obj in objs:
                # 找的策略是：找到一个就结束
                print("[INFO] config: ", config, " src: ", src, " obj: ", obj)
                bc, result = get_child_node_by_path(root_node, obj)
                if result == 0:
                    # print("Damn! I did not find the directory node ", src)
                    # 没找到这个目录节点
                    # 如果是arch目录下的文件，可能是因为没有编译该架构的内核，此时不做处理
                    if src.startswith("arch/"):
                        print("[WARNING] %s is not compiled, skip" % src)
                    else:
                        print("[WARNING] %s is not found, skip" % src)
                    continue
                # 由于不采用built-in，因此这一分支去除
                # elif result == 1:
                #     # 没找到对应的文件，但找到了目录节点
                #     # 使用目录节点下的built-in.bc文件
                #     bc = os.path.join(bc, "built-in.bc")
                #     #print("Found the directory node ", src, "in", bc)
                #     if not os.path.exists(bc):
                #         print("[WARNING] %s is not found, skip" % bc)
                #         continue
                else:
                    print("Yes! I found the directory node ", src, "in", bc)

                # 去重后加入列表
                if (bc is not None) and (bc not in config_bcs[config]):
                    config_bcs[config].append(bc)
                    size += os.path.getsize(os.path.join(kernel_build_dir, bc))

                    # 如果超限就要缩
                    if size > MAX_SIZE:
                        print("[WARNING] %s size %d exceeds MAX_SIZE, trimming..." % (config, size))
                        config_bcs[config] = []
                    
                    break

    return config_bcs

def sort_config_bcs(config_bcs):
    # 对config_bcs内每个config对应的bcs列表按名称排序
    for config, bcs in config_bcs.items():
        bcs.sort()
    return config_bcs

def reverse_dict(config_bcs):
    # 给每个bcs列表分配一个索引，这是索引到列表的字典
    bcs_index = {}
    # 这是索引到对应配置项的字典
    index_config = {}
    bcs = []
    index = 0
    for config, bcs_list in config_bcs.items():
        if bcs_list is None:
            # 空列表，啥也不干
            # print("Empty list. Do nothing.")
            continue
        if bcs_list not in bcs:
            # 这个列表之前没分配过索引
            # print("An unallocated list. Allocating...")
            bcs.append(bcs_list)
            bcs_index[index] = bcs_list
            bcs2index = str(index)
            index += 1
        else:
            # 这个列表之前分配过索引
            # 拿到它对应的索引
            # print("An allcoated list. Searching for the index.")
            for i, bcs_item in bcs_index.items():
                if bcs_item == bcs_list:
                    bcs2index = str(i)
                    break
        if bcs_index.get(bcs2index) == None:
            # print("Nein.")
            index_config[bcs2index] = []
        index_config[bcs2index].append(config)

    return bcs_index, index_config

# if __name__ == "__main__":
#     root_node, bcgroups = auto_collect_bcs()
#     src = "kernel/kthread.c"
#     src = src.replace("/home/jiakai/tmp/linux", "")
#     if src.startswith('/'):
#         src = src[1:]
#     bc, result = get_child_node_by_path(root_node, src)
#     print(bc)
#     print(result)

if __name__ == "__main__":
    # Automatically collect target bc files to analyze
    root_node, bcgroups = auto_collect_bcs()
    print("total # groups %d" % len(bcgroups))
    print(bcgroups)
    import json
    # 这个路径可能要改一下，或者在你的自动化脚本中用代码传输
    with open("/home/jiakai/KConfigFuzz/config/config_codeblock.json", "r") as f:
        config_codeblocks = json.load(f)
    # 这个路径同理
    with open("/home/jiakai/tmp/linux/dependencies.yaml", 'r') as f:
        obj_srcs = yaml.load(f)
    # 将数据反转过来，提升效率
    # 注意数据里有通配符哈
    print("reading completed.")
    src_objs = {}
    for obj, src in obj_srcs['dependencies'].items():
        if src == None:
            continue
        sources = []
        if src.get("sources"):
            sources = sources + src["sources"]
        if src.get("headers"):
            sources = sources + src["headers"]
        for source in sources:
            if src_objs.get(source) is None:
                src_objs[source] = [obj, ]
            elif obj not in src_objs[source]:
                src_objs[source].append(obj)
    # print(src_objs)
    config_bcs = arrange_bcs_by_config(bcgroups, root_node, config_codeblocks, src_objs)
    print("hello")
    print(config_bcs)
    print("goodbye")
    # Sort the config_bcs by name
    config_bcs = sort_config_bcs(config_bcs)
    # Due to one bc list may correspond to several configs, we need to reverse this dict into bc_list -> configs
    bcs_index, index_config = reverse_dict(config_bcs)
    # Store them
    with open("bcs_index.json", "w+") as f:
        json.dump(bcs_index, f)
    with open("index_config.json", "w+") as f:
        json.dump(index_config, f)

    DFS(root_node)

    # Use pre-defined bc file list
    # analyze(bcs_index,bcgroups)