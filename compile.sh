#!/bin/bash

LLVMLINK=/home/jiakai/tmp/llvm-link-bc.sh

# 配置路径
SRC_DIR="/home/jiakai/tmp/linux"          # 内核源码目录
OUTPUT_DIR="/home/jiakai/tmp/linux_bc_test"    # 输出目录
CLANG_PATH="/home/jiakai/tools/clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04/bin/clang"    # clang编译器路径
#CLANG_PATH="/usr/local/llvm-15/bin/clang"
CPU_NUM=$(nproc)               # 使用所有CPU核心

# 创建emit-llvm脚本
EMIT_SCRIPT="/home/jiakai/tmp/emit_llvm.sh"

cat > $EMIT_SCRIPT << 'EOF'
#!/bin/sh
CLANG=$1
shift
OFILE=`echo $* | sed -e 's/^.* \(.*\.o\) .*$/\\1/'`
if [ "x$OFILE" != x -a "$OFILE" != "$*" ] ; then
    $CLANG -emit-llvm -g -O1 "$@" >/dev/null 2>&1
    if [ -f "$OFILE" ] ; then
        BCFILE=`echo $OFILE | sed -e 's/o$/bc/'`
        if [ $(file $OFILE | grep -c "LLVM IR bitcode") -eq 1 ]; then
            mv $OFILE $BCFILE
        else
            touch $BCFILE
        fi
    fi
fi
exec $CLANG "$@"
EOF

chmod +x $EMIT_SCRIPT

# 创建llvm-link-bc脚本

cat > $LLVMLINK << 'EOF'
#!/bin/bash

set -e

LD=ld
LLVM_LINK=llvm-link

# link llvm bitcode files

OPT=$*
F=0
NEW=

NUM=0
PREV=

#TODO: To many corner cases...
for TOK in $OPT
do
  case "$TOK" in
    "-r"|"-m"|"elf_x86_64"|"--emit-relocs"|"-T"|"--start-group"|"--end-group"|*.lds|*.ld|*.a|*.ver)
      continue
      ;;
  esac

  REP=$(echo $TOK | sed -e 's/\.o/\.bc/g')
  if [[ $TOK != '-o' ]] && [[ $PREV != '-o' ]] && [[ ! -f "$REP" ]]; then
    # File not exists
    PREV=$TOK
    continue
  fi

  # TODO: Fix it
  if [[ $PREV = '-o' ]] && [[ $REP =~ '\.bc' ]]; then
    REP=$REP.bc
  fi

  PREV=$TOK
  NEW+=$REP' '
  NUM=`expr $NUM + 1`
done

if [ $NUM -ge 3 ];
then
  $LLVM_LINK $NEW
fi

$LD $*
EOF

chmod +x $LLVMLINK

# 准备输出目录
mkdir -p $OUTPUT_DIR

# 进入源码目录
cd $SRC_DIR

# 清理之前的编译
make clean
make mrproper

# 编译内核生成bitcode
echo "开始编译内核生成bitcode..."
# 以防万一，还修改了Makefile中的-O2为-O0
make CC="$EMIT_SCRIPT $CLANG_PATH" O=$OUTPUT_DIR KCFLAGS+="-O1" LD="${LLVMLINK}" defconfig
make CC="$EMIT_SCRIPT $CLANG_PATH" O=$OUTPUT_DIR KCFLAGS+="-O1" LD="${LLVMLINK}" -j$CPU_NUM

echo "编译完成！bitcode文件已生成在 $OUTPUT_DIR 目录中"

