#!/bin/bash
#
# extract-kernel-dependencies.sh
#
# 在内核源码顶层运行，生成 dependencies.yaml
# Usage: ./extract-kernel-dependencies.sh [make-target]
#   默认 target=vmlinux，也可指定 all modules 等
#

set -euo pipefail

export ARCH=riscv
export CROSS_COMPILE=riscv64-unknown-linux-gnu-
export PATH="/home/temp/tools/riscv/bin:$PATH"

# 1) 可根据需要修改的变量
MAKE_CMD=make        # 使用 make 或 remake
TARGET=${1:-vmlinux} # 默认目标
DB_FILE=remake-db.txt
OUT=dependencies.yaml

echo "==> 1) 用 '$MAKE_CMD -n -p $TARGET' 打印内部数据库到 $DB_FILE"
$MAKE_CMD -n -p $TARGET > $DB_FILE 2>/dev/null || {
    echo "警告：构建数据库时遇到错误，继续处理已有数据" >&2
}

echo "==> 2) 生成 YAML 依赖文件: $OUT"

# 开始写入 YAML 文件
echo "---" > $OUT
echo "# 内核构建依赖关系" >> $OUT
echo "# 生成时间: $(date)" >> $OUT
echo "# 构建目标: $TARGET" >> $OUT
echo "dependencies:" >> $OUT

# 提取所有 .o 目标及其依赖
grep -E '^[^#%][^:]*\.o:' $DB_FILE | while IFS= read -r rule_line; do
    # 提取目标文件名 (移除尾部冒号)
    object=$(echo "$rule_line" | awk -F ':' '{print $1}' | xargs)
    
    # 提取所有依赖项
    deps=$(echo "$rule_line" | awk -F ':' '{print $2}' | xargs)
    
    # 过滤出源文件 (.c, .S, .s) 和头文件 (.h)
    source_files=""
    header_files=""
    
    for dep in $deps; do
        case "$dep" in
            *.c|*.S|*.s)
                source_files+="$dep "
                ;;
            *.h)
                # 只包含实际存在的头文件
                if [ -f "$dep" ]; then
                    header_files+="$dep "
                fi
                ;;
        esac
    done
    
    # 移除多余空格
    source_files=$(echo "$source_files" | xargs)
    header_files=$(echo "$header_files" | xargs)
    
    # 写入 YAML 格式
    echo "  $object:" >> $OUT
    if [ -n "$source_files" ]; then
        echo "    sources:" >> $OUT
        for src in $source_files; do
            echo "      - \"$src\"" >> $OUT
        done
    fi
    
    if [ -n "$header_files" ]; then
        echo "    headers:" >> $OUT
        for hdr in $header_files; do
            echo "      - \"$hdr\"" >> $OUT
        done
    fi
done

echo "==> 3) 添加未直接关联的额外头文件"
# 查找所有内核头文件
find . -type f \( -name '*.h' -o -name '*.hpp' \) > all_headers.txt

# 添加到 YAML 中未包含的头文件
grep -E '^[^#%][^:]*\.o:' $DB_FILE | awk -F ':' '{print $1}' | sort -u | while read -r object; do
    if ! grep -q "^  $object:" $OUT; then
        echo "  $object:" >> $OUT
        echo "    sources: []" >> $OUT
        echo "    headers: []" >> $OUT
    fi
done

echo "==> 4) 清理临时文件"
rm -f $DB_FILE all_headers.txt

echo "==> 完成! 依赖关系已保存到 $OUT"
echo "==> 共处理 $(grep -c '^  [^ ]' $OUT) 个对象文件"
