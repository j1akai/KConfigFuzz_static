from __future__ import print_function
from concurrent.futures import ProcessPoolExecutor, as_completed
import os
import json
from functools import partial

# ===== 配置区域 =====
NUM_PROC = 16  # 推荐设为 CPU 物理核心数（可通过 lscpu 查看）
kernel_build_dir = "/home/jiakai/tmp/linux_bc_test"
ANALYSIS_OUTPUT_DIR = "./output"  # 与 shell 脚本一致
SCRIPT_PATH = "./partitioned_analysis.sh"

# 创建 output 目录
os.makedirs(ANALYSIS_OUTPUT_DIR, exist_ok=True)

# ===== 工具函数 =====
def task_exists(i):
    """检查第 i 个任务是否已完成（通过检查 mssa.i 文件）"""
    mssa_path = os.path.join(ANALYSIS_OUTPUT_DIR, f"mssa.{i}")
    return os.path.isfile(mssa_path) and os.path.getsize(mssa_path) > 0

def do_analyze_one(i, total, bcs, skip_if_exists=True):
    """
    单个分析任务
    :param i: 任务索引
    :param total: 总数（用于打印）
    :param bcs: .bc 文件路径列表（相对 kernel_build_dir）
    :param skip_if_exists: 若输出已存在，跳过
    """
    # 检查是否已存在结果
    if skip_if_exists and task_exists(i):
        print(f"[{i}/{total}] SKIPPED (already analyzed)")
        return i, True, "already done"

    # 构造完整路径并验证存在性
    bc_paths = []
    for bc in bcs:
        full_path = os.path.join(kernel_build_dir, bc)
        if not os.path.exists(full_path):
            print(f"[ERROR] Missing .bc file: {full_path}")
            return i, False, "missing bc"
        bc_paths.append(bc)

    bcs_str = " ".join(bc_paths)
    analysis_title = f"{i}.bc"
    print(f"[{i}/{total}] STARTING: {len(bc_paths)} files -> {analysis_title}")

    cmdstr = f"{SCRIPT_PATH} {i} {bcs_str}"
    exit_status = os.system(cmdstr)

    if exit_status != 0:
        print(f"[{i}/{total}] FAILED: {analysis_title}")
        return i, False, "cmd failed"
    else:
        print(f"[{i}/{total}] COMPLETED: {analysis_title}")
        return i, True, "success"

def analyze(bcs_index, index_config):
    bcgroups = list(bcs_index.values())
    total = len(bcgroups)
    print(f"Total tasks: {total}, Parallel workers: {NUM_PROC}")

    with ProcessPoolExecutor(max_workers=NUM_PROC) as executor:
        # 手动传所有参数，不依赖 partial
        futures = [
            executor.submit(do_analyze_one, i, total, bcgroups[i], True)
            for i in range(total)
        ]

        completed = 0
        for future in as_completed(futures):
            i, success, msg = future.result()
            completed += 1
            status = "OK" if success else "FAIL"
            print(f"[PROGRESS] {completed}/{total} | Task {i}: {status} ({msg})")

    print("✅ All analysis tasks completed.")

# ===== 主函数 =====
if __name__ == '__main__':
    bcs_index, index_config = None, None

    if os.path.exists("bcs_index.json"):
        with open("bcs_index.json", "r") as f:
            bcs_index = json.load(f)
    else:
        print("❌ bcs_index.json not found. Please run run-partition-analysis.py first.")
        exit(1)

    if os.path.exists("index_config.json"):
        with open("index_config.json", "r") as f:
            index_config = json.load(f)
    else:
        print("❌ index_config.json not found. Please run run-partition-analysis.py first.")
        exit(1)

    print("✅ Found bcs_index.json and index_config.json")

    analyze(bcs_index, index_config)