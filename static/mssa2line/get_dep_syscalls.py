import json

bb2srcRange = {}
kernelCode2syscall = {}
# 先存储成这个样子，后面再改成其他格式
# 默认读在前，写在后
dependent_syscalls = []

if __name__ == "__main__":
    dependent_ops_src = 'dependent_ops.txt'
    bb2srcRange_src = '/home/jiakai/KConfigFuzz/static/line2syscall/bb2srcRange'
    kernelCode2syscall_src = '/home/jiakai/KConfigFuzz/static/line2syscall/output/kernelCode2syscall.json'

    for line in open(bb2srcRange_src, 'r'):
        line_split = line.strip().split(' ')
        if len(line_split) < 5:
            continue
        # print(line_split)
        src, func, idx, begin, end = line_split[0], line_split[1], line_split[2], line_split[3], line_split[4]
        src = src.replace('/home/jiakai/tmp/linux/', '')
        line_range_idx = begin + '-' + end
        if not bb2srcRange.get(src):
            bb2srcRange[src] = {line_range_idx : func + ':' + idx}
        else:
            bb2srcRange[src][line_range_idx] = func + ':' + idx

    with open(kernelCode2syscall_src, 'r') as f:
        kernelCode2syscall = json.load(f)

# 注意idx可能是none（注意第一个字母小写）
    for line in open(dependent_ops_src, 'r'):
        write_syscall, read_syscall = None, None
        line_split = line.strip().split(':')
        read_src, read_line, write_src, write_line = line_split[0], int(line_split[1]), line_split[2], int(line_split[3])
        read_func, write_func = None, None
        read_func_idx, write_func_idx = None, None
        if (not bb2srcRange.get(read_src)) or (not bb2srcRange.get(write_src)):
            continue
        for line_range_idx, func_and_idx in bb2srcRange[read_src].items():
            line_range_idx_split = line_range_idx.split('-')
            begin, end = int(line_range_idx_split[0]), int(line_range_idx_split[1])
            if begin <= read_line <= end:
                func_and_idx_split = func_and_idx.split(':')
                read_func = func_and_idx_split[0]
                read_func_idx = func_and_idx_split[1]
                break
        for line_range_idx, func_and_idx in bb2srcRange[read_src].items():
            line_range_idx_split = line_range_idx.split('-')
            begin, end = int(line_range_idx_split[0]), int(line_range_idx_split[1])
            if begin <= write_line <= end:
                func_and_idx_split = func_and_idx.split(':')
                write_func = func_and_idx_split[0]
                write_func_idx = func_and_idx_split[1]
                break
        if read_func == None or write_func == None or read_func == write_func:
            continue
        dependent_syscall_pair = read_func + ':' + write_func
        dependent_syscall_pair_reverse = write_func + ':' + read_func
        if dependent_syscall_pair in dependent_syscalls or dependent_syscall_pair_reverse in dependent_syscalls:
            continue
        dependent_syscalls.append(dependent_syscall_pair)
        print(write_func, read_func)
        # if kernelCode2syscall.get(write_func) == None or kernelCode2syscall.get(read_func) == None:
        #     continue
        # if "none" in kernelCode2syscall[write_func]:
        #     write_syscall = kernelCode2syscall[write_func]["none"]
        # elif kernelCode2syscall[write_func].get(write_func_idx) != None:
        #     write_syscall = kernelCode2syscall[write_func].get(write_func_idx)
        # if "none" in kernelCode2syscall[read_func]:
        #     read_syscall = kernelCode2syscall[read_func]["none"]
        # elif kernelCode2syscall[read_func].get(read_func_idx) != None:
        #     read_syscall = kernelCode2syscall[read_func].get(read_func_idx)
        # if write_syscall == None or read_syscall == None:
        #     continue
        # print(write_syscall, read_syscall)
        