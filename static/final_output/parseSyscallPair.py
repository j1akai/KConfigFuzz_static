#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import subprocess
import re
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# 线程锁，用于安全写入共享的地址字典（虽然这里不是必须，但确保安全）
addresses_lock = threading.Lock()

def get_address_from_source(image_path, source_path, line_number):
    """
    使用 GDB 推测给定 Linux 镜像中源码文件和行号对应的虚拟地址。
    （函数内容未变）
    """
    if not os.path.exists(image_path):
        return None
    try:
        line = int(line_number)
    except (ValueError, TypeError):
        return None

    gdb_command = [
        'gdb',
        '-q',
        '-batch',
        '-ex', f'file {image_path}',
        '-ex', f'info line {source_path}:{line}',
    ]

    try:
        result = subprocess.run(
            gdb_command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )
    except FileNotFoundError:
        sys.stderr.write("Error: 'gdb' command not found. Please ensure GDB is installed and in your PATH.\n")
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        sys.stderr.write(f"An unexpected error occurred while running GDB: {e}\n")
        return None

    stdout = result.stdout
    if "No line" in stdout or "contains no code" in stdout:
        return None

    match = re.search(r'starts at address (0x[0-9a-fA-F]+)', stdout)
    if match:
        return match.group(1)
    else:
        return None


def worker(image_path, item):
    """
    工作线程函数：处理单个 syscallPair 条目。
    返回 key 和地址结果。
    """
    key = (item["Source"], item["Line"])
    address = get_address_from_source(image_path, item["Source"], item["Line"])
    return key, address, item["Source"], item["Line"], address


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.stderr.write(f"Usage: python3 {sys.argv[0]} <vmlinux_path> <syscallPair_path>\n")
        sys.stderr.write(f"Example: python3 {sys.argv[0]} ./vmlinux syscallPair.json\n")
        sys.exit(1)

    vmlinux_path = sys.argv[1]
    syscallPair_path = sys.argv[2]

    # 读取 syscallPair
    with open(syscallPair_path, 'r') as f:
        syscallPair = json.load(f)

    print("I have read it.")

    # 存储结果
    addresses = {}
    final = []
    total = len(syscallPair)
    processed = 0

    # 使用线程池（推荐线程数为CPU核心数的2-4倍，但GDB是外部I/O，可设高一些）
    max_workers = 16  # 可以根据自己的机器调整

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_item = {
            executor.submit(worker, vmlinux_path, item): item for item in syscallPair
        }

        for future in as_completed(future_to_item):
            key, address, source, line, addr_result = future.result()
            processed += 1

            # 全局记录地址
            with addresses_lock:
                addresses[key] = address

            if address is not None:
                print(f"[{processed}/{total}] Source: {source} Line: {line} Address: {address}")
            else:
                print(f"[{processed}/{total}] Source: {source} Line: {line} --> Failed")

    # 生成最终输出
    for item in syscallPair:
        address = addresses.get((item["Source"], item["Line"]))
        if address is not None:
            final.append({
                "Target": item["Target"],
                "Relate": item["Relate"],
                "Addr": address
            })

    with open("syscallPair_new.json", 'w') as f:
        json.dump(final, f, indent=2)

    print(f"Done. Wrote {len(final)} entries to syscallPair_new.json")