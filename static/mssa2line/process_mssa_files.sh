#!/bin/bash

# 定义目录路径
input_dir="/home/jiakai/KConfigFuzz/static/bc2mssa/output"
config_codeblock="/home/jiakai/KConfigFuzz/config/config_codeblock.json"
config_tree="/home/jiakai/KConfigFuzz/config/config_tree.json"
script="python3 get_dep_pairs.py"

# 检查输入目录是否存在
if [ ! -d "$input_dir" ]; then
    echo "错误：目录 $input_dir 不存在"
    exit 1
fi

# # 遍历所有以mssa开头的文件
# for file in "$input_dir"/mssa*; do
#     # 确保是文件而不是目录
#     if [ -f "$file" ]; then
#         echo "正在处理文件: $file"
#         # 执行命令
#         $script "$file" --config_codeblock_path "$config_codeblock" --config_tree_path "$config_tree"
        
#         # 检查命令是否成功执行
#         if [ $? -ne 0 ]; then
#             echo "错误：处理文件 $file 时出错"
#         else
#             cat result_related2.txt >> dependent_ops.txt
#         fi
#     fi
# done

$script "$input_dir" --config_codeblock_path "$config_codeblock" --config_tree_path "$config_tree"

echo "所有文件处理完成"
