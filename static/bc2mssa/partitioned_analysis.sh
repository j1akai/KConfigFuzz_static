#!/bin/bash -e

NAME=$1
echo "[*] NAME: [$NAME]"
shift

echo "[*] Making static analysis directory"
ANALYSIS_DIR=./output
mkdir -p $ANALYSIS_DIR
DIR=$(realpath "./output/")
echo "[*] DIR:" $DIR

pushd $DIR >> /dev/null

BUILD_DIR=/home/jiakai/tmp/linux_bc_test

# 根据传入的路径去找.bc文件
BCFILES=""
for param in "$@"
do
    BC=$BUILD_DIR/$param
    if [ ! -f $BC ]; then
        echo "[ERROR] Cannot find .bc file: $BC"
        exit 1
    fi
    BCFILES="$BCFILES $BC"
done

# 先使用llvm-link将多个.bc文件合并到一起
if [ ! -s ./combined.$NAME.bc ]; then
    echo "[*] Generating combined-$NAME.bc"
    rm -f combined.$NAME.bc
    llvm-link $BCFILES -o combined.$NAME.bc
fi

# 执行ssa(static single assignment)转换
if [ ! -s ./mssa.$NAME ]; then
    echo "[*] Generating mssa.$NAME"
    rm -f ./mssa.$NAME
    svf-ex -ind-call-limit=100000 -ander --svfg --dwarn --dump-mssa ./combined.$NAME.bc > ./mssa.$NAME
    # python /home/jiakai/KConfigFuzz/static/bc2mssa/analysis.py ./combined.$NAME.bc > ./mssa.$NAME
    rm combined.$NAME.bc
fi

# 这部分代码由于为了测试故未执行
# if [ ! -s ./mempair_all.$NAME ]; then
#     echo "[*] Generating mempair_all.$NAME"
#     rm -f ./mempair_all.$NAME
#     get_aliased_pair_in_config_new.py ./mssa.$NAME > ./mempair_all.$NAME
# fi

# if [ ! -s ./mempair.$NAME ]; then
#     echo "[*] Prune and check_testing_bugs"
#     rm -f ./mempair.$NAME
#     prune.py ./mempair_all.$NAME > ./mempair.$NAME
#     check_testing_bugs.py ./mempair.$NAME
# fi

ls -lh *$NAME*
popd 2>/dev/null

