#!/usr/bin/python

import os
import sys
import argparse

parser = argparse.ArgumentParser(description='Analyze the given bitcode using wpa')
parser.add_argument('bitcode')

args = parser.parse_args()

# 这个cmd是调用SVF的命令
# -vgep Hanle variant gep/field edge
# 使用 --ff-eq-base + --model-arrays 替代 -vgep，--dump-uninit-ptr + --dump-free 替代 -dump-race
# 现在有一个问题：就是SVF并不是把所有的读写指令都做分析，有时间时请你研究一下是否是我们调用SVF的参数不对？
# cmd = "wpa -indCallLimit=100000 -dump-callgraph -ander -vgep -svfg -dump-mssa -dump-race " + args.bitcode
# cmd = "wpa -ind-call-limit=100000 -dump-callgraph -ander -svfg -dump-mssa " + args.bitcode
cmd = "svf-ex -ind-call-limit=100000 -ander --svfg --dump-mssa " + args.bitcode
os.system(cmd)
