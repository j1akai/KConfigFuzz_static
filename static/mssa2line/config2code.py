import json

class Config2Code():
    def __init__(self, config_codeblock_path, config_tree_path):
        with open(config_codeblock_path, 'r') as f:
            self.config_codeblock = json.load(f)
            print("Loaded config codeblocks successfully.")
        with open(config_tree_path, 'r') as f:
            self.config_tree = json.load(f)
            print("Loaded config tree successfully.")
        # 注意！！！一定要注意这里！！！
        # 由于传入的地址是绝对地址，即会把Linux源码的地址给传进去，这会为匹配路径造成困难。
        # 这里为了测试，把传入的Linux源码的地址写死了，这里记得要改！！！
        self.kernel_dir = "/home/jiakai/tmp/linux/"
        self.convert_config_codeblock()
        self.new_created_config_idx = 0
        self.possibly_incorrect_config_info = []
        print("Converted config codeblocks successfully.")
        # del self.config_codeblock
        # with open("tmp.json", 'w+') as f:
        #     json.dump(self.codeblock_config, f)

    def convert_config_codeblock(self):
        self.codeblock_config = {}
        for config, data in self.config_codeblock.items():
            for src, ranges in data.items():
                if self.codeblock_config.get(src) is None:
                    self.codeblock_config[src] = {}
                
                if [0, 0] in ranges:
                    self.codeblock_config[src][config] = [[0, 0]]
                    continue

                for lines in ranges:
                    if self.codeblock_config[src].get(config) is None:
                        self.codeblock_config[src][config] = [lines, ]
                    if lines not in self.codeblock_config[src][config]:
                        self.codeblock_config[src][config].append(lines)
    
    def code2config(self, src, line):
        # 寻找一行代码对应的配置项
        # 如果没有返回None

        # 注意！！！一定要注意这里！！！
        # 由于传入的地址是绝对地址，即会把Linux源码的地址给传进去，这会为匹配路径造成困难。
        # 这里为了测试，把传入的Linux源码的地址写死了，这里记得要改！！！
        # 可以把这个关掉，看config_codeblock在每一步的内容有什么不同，你就会发现端倪。
        src = "/home/jiakai/tmp/linux/" + src

        if self.codeblock_config.get(src) is None:
            return None
        configs = set()
        for config, ranges in self.codeblock_config[src].items():
            if [0, 0] in ranges:
                configs.add(config)
                continue
            for lines in ranges:
                if lines[0] <= line <= lines[1]:
                    configs.add(config)
                    continue
        if len(configs) == 0:
            return None
        return configs
    
    def config2code(self, config):
        # 根据配置项获取对应的代码块
        # 如果没有返回None
        if self.config_codeblock.get(config) is None:
            return None
        return self.config_codeblock[config]
    
    def get_related_configs(self, config):
        # 获取与配置项相关的配置项（父/子节点）
        # 如果没有返回空列表
        related_configs = []
        childs = self.get_child_configs(config)
        parents = self.get_parent_configs(config)
        # 将子节点和父节点合并
        related_configs.extend(childs)
        related_configs.extend(parents)
        return related_configs
    
    def get_child_configs(self, config):
        # 获取配置项的子节点
        # 如果没有返回空列表
        result = set()
        for c in config:
            result.update(self.config_tree.get(c, []))
        return result
    
    def get_parent_configs(self, config):
        # 获取配置项的父节点
        # 如果没有返回空列表
        parents = []
        for parent, childs in self.config_tree.items():
            if config in childs:
                parents.append(parent)
        return parents
    
    def are_related_configs(self, config1, config2):
        # 判断两个配置项是否相关
        # 如果相关返回True，否则返回False
        if config1 == config2:
            return True
        if config2 in self.get_child_configs(config1):
            return True
        if config1 in self.get_child_configs(config2):
            return True
        return False

    def process_possibly_incorrect_configs(self, store_insn, load_insn):
        # 处理可能有错的配置项关系
        cb = None
        extract_one = 0
        dependent_config = None
        store_src = store_insn.src
        store_line = store_insn.line
        load_src = load_insn.src
        load_line = load_insn.line
        store_configs = store_insn.config
        load_configs = load_insn.config
        # 关系错误：本应有依赖但没依赖
        # 默认的方式是让读配置项依赖于写配置项
        # 同时保留两个配置项本有的依赖关系
        # 如果写配置项管辖着写语句所在的整个文件，此时让写配置项管辖的所有代码给读配置项做依赖并不合适
        # 因此将那段有依赖关系的代码块抽取出来，被一个新的配置项管辖
        # 独立作为读配置项的父节点
        # 如果这么做了，这个函数就返回这个配置项

        # 首先将写语句所在的代码块找出来
        store_src2 = self.kernel_dir + store_src
        for store_config in store_configs:
            write_codeblocks = self.config2code(store_config)
            # print(write_codeblocks)
            for codeblock in write_codeblocks[store_src2]:
                if codeblock == None:
                    continue
                if codeblock[0] == 0:
                    # 代表整个文件都被包裹
                    extract_one = 1
                    dependent_config = store_config
                    break
                if codeblock[0] <= int(store_line) <= codeblock[1]:
                    extract_one = 2
                    cb = codeblock
                    dependent_config = store_config
                    break

        # 找到写语句所在的代码块
        if extract_one == 1:
            codeblock_begin = store_line - 10 if store_line - 10 > 0 else 1
            codeblock_end = store_line + 10
            cb = [codeblock_begin, codeblock_end]

        if cb == None:
            return None
        
        # 现在需要将这个代码块抽取出来，作为一个新的配置项
        new_config = f"NEW_CONFIG_{self.new_created_config_idx}"
        # 将新配置项添加到codeblock_config, config_tree中
        self.config_codeblock[new_config] = {store_src2: [cb]}
        self.codeblock_config[store_src2][new_config] = [cb, ]
        # 新的写配置项依赖于原配置项，读配置项依赖于新写配置项
        self.config_tree[new_config] = [dependent_config]
        for load_config in load_configs:
            if load_config not in self.config_tree:
                self.config_tree[load_config] = [new_config]
            else:
                self.config_tree[load_config].append(new_config)
        # 更新新配置项的索引
        self.new_created_config_idx += 1
        # 更新新配置的信息
        self.possibly_incorrect_config_info.append({
            'store_configs': store_configs,
            'store_src': store_src,
            'store_line': store_line,
            'load_configs': load_configs,
            'load_src': load_src,
            'load_line': load_line,
            'new_config': new_config,
            'codeblock': cb
        })
        return new_config
    
    def print_possibly_incorrect_configs(self):
        with open("possibly_wrong_configs.json", 'w+') as f:
            json.dump(self.possibly_incorrect_config_info, f)