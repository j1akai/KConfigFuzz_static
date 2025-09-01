import json, os

rcalltrimthreshold=10
filesystems=["sysfs", "rootfs", "ramfs", "tmpfs", "devtmpfs", "debugfs", "securityfs", "sockfs", "pipefs", "anon_inodefs", "devpts", "ext3", "ext2", "ext4", "hugetlbfs", "vfat", "ecryptfs", "fuseblk", "fuse", "rpc_pipefs", "nfs", "nfs4", "nfsd", "binfmt_misc", "autofs", "xfs", "jfs", "msdos", "ntfs", "minix", "hfs", "hfsplus", "qnx4", "ufs", "btrfs", "configfs", "ncpfs", "qnx6", "exofs", "befs", "vxfs", "gfs2","gfs2meta", "fusectl", "bfs", "nsfs", "efs", "cifs", "efivarfs", "affs", "tracefs", "bdev", "ocfs2", "ocfs2_dlmfs", "hpfs", "proc", "afs", "reiserfs", "jffs2", "romfs", "aio", "sysv", "v7", "udf", "ceph", "pstore", "adfs", "9p", "hostfs", "squashfs", "cramfs", "iso9660", "coda", "nilfs2", "logfs", "overlay", "f2fs", "omfs", "ubifs", "openpromfs", "bpf", "cgroup", "cgroup2", "cpuset", "mqueue", "aufs", "selinuxfs", "dax", "erofs", "virtiofs", "exfat", "binder", "zonefs", "pvfs2", "incremental-fs", "esdfs"]
syscallblacklist=["mq_open","syz_open_procfs","epoll_create","eventfd","signalfd","timerfd_create","pidfd_open","pidfd_getfd", "memfd_create","memfd_secret"]

def LoadJson(filename):
    data = None
    with open(filename, 'r') as f:
        data = json.load(f)
    return data

def ParseConstraint(filename, recommend_syscalls=[]):
    runCase2cst = dict()
    new_tcall_res = dict()
    new_index2sys = dict()
    
    labels = ["Name", "Value", "Type"]
    rawItems = LoadJson(filename)
    
    for xidxItem in rawItems:
        xidx = int(xidxItem['case index'])

        xCsts = {}
        isInvalid = True 
        
        for cinfo in xidxItem['target syscall infos']:
            callCsts = cinfo['constraints']
            target_call = cinfo['target syscall']
            for cstType, currTypeCsts in callCsts.items():
                if cstType == "int":
                    for currCst in currTypeCsts:
                        cstVal = int(currCst['value'])
                        assert cstVal >= 0
                        xCsts[currCst['name']] = (cstVal, cstType, target_call)
                elif cstType == "string":
                    currCst = currTypeCsts
                    xCsts[currCst] = (0, 'str', target_call)
                else:
                    print(f'[xidx {xidx}]Unexpected value...Something went wrong... cstType: {cstType}') 
                    
            if len(callCsts) == 0: 
                xCsts['invalid_abc'] = (0, "invalid", target_call)
            else:
                isInvalid = False 
        
        if isInvalid: 
            xCsts.clear()
        
        formatCsts = list([
                dict(zip(labels, [cstName, *cstItem]))
                for cstName, cstItem in xCsts.items()
        ])
        
        new_tcall_res[xidx] = {}
        new_index2sys[xidx] = set()
        for cinfo in xidxItem['target syscall infos']:
            rawTcall = cinfo['target syscall']
            rank = cinfo['rank']
            if "$" in rawTcall:
                rawTcall = rawTcall[:rawTcall.find("$")]    
            if rank not in new_tcall_res[xidx]:
                new_tcall_res[xidx][rank] = []

            new_index2sys[xidx].add(rawTcall)
            new_tcall_res[xidx][rank].append(cinfo['target syscall'])
                   

        runCase2cst[xidx] = formatCsts
        
    if len(recommend_syscalls)>0:
        idx_xidx_calls = FilterSyscall(new_index2sys, new_tcall_res, recommend_syscalls=[])
    else:   
        
        idx_xidx_calls=dict()
        
        for xidx,rankMap in new_tcall_res.items():
            for rank, tcalls in rankMap.items():
                if xidx not in idx_xidx_calls.keys():
                    idx_xidx_calls[xidx] = set()
                for call in tcalls:
                    idx_xidx_calls[xidx].add(call)
        
        print(idx_xidx_calls)
        
    
    return runCase2cst, idx_xidx_calls
    

def FilterSyscall(new_index2sys, new_tcall_res, recommend_syscalls):
    MAX_TCALL_RANK = 2

    new_final_index2tcall = dict() # xidx -> tcall
    
    for xidx, tcall_ori in new_index2sys.items():
        new_final_index2tcall[xidx] = set()

        tcall_res_idx = new_tcall_res[xidx]
        tcall_res_idx_sorted = sorted(tcall_res_idx.items(), key=lambda x:x[0])
        
        if len(recommend_syscalls)>0:
            # crash mode
            for recommend_tcall in recommend_syscalls:
                if recommend_tcall in tcall_ori:
                    rank_now = 0
                    for tcall_res_idx_sorted_item in tcall_res_idx_sorted:
                        if rank_now > MAX_TCALL_RANK:
                            break
                        rank = tcall_res_idx_sorted_item[0]
                        sys_list = tcall_res_idx_sorted_item[1]
                        match_flag = False
                        for sys in sys_list:
                            if "$" not in sys:
                                if sys == recommend_tcall:
                                    new_final_index2tcall[xidx].add(sys)
                                    match_flag = True
                            else:
                                real_sys = sys.split("$")[0]
                                if real_sys == recommend_tcall:
                                    new_final_index2tcall[xidx].add(sys)
                                    match_flag = True

                        if match_flag:
                            rank_now += 1
                else:
                    new_final_index2tcall[xidx].add(recommend_tcall)
        else:
            for ri, tcall_res_idx_sorted_item in enumerate(tcall_res_idx_sorted, start=1):
                if ri > MAX_TCALL_RANK:
                    break
                rank = tcall_res_idx_sorted_item[0]
                sys_list = tcall_res_idx_sorted_item[1]
                for sys in sys_list:
                    new_final_index2tcall[xidx].add(sys)

    return new_final_index2tcall

def GetRawCallName(call):
    if call.endswith("_rf1"):
        if call.endswith("$tmp_rf1"):
            call = call[:len(call) - 8]
        else:
            call = call[:len(call) - 4]
    return call

def GetGeneralCallName(call):
    if "$" in call:
        call = call[:call.find("$")]
    if call == "syz_mount_image":
        call = "mount"
    return call 

def FilterGeneralSyscall(calls):
    shouldRemove = set()
    for call in calls:
        if "$" in call:
            rawCall = call[:call.find("$")]
            if rawCall in calls:
                shouldRemove.add(rawCall)
    for rawcall in shouldRemove:
        calls.remove(rawcall)
    return calls


if __name__ == '__main__':
    DependetOpsfileName = "/home/jiakai/KConfigFuzz/static/mssa2line/dependent_ops.txt"
    StaticAnalysisfileName =  "/home/jiakai/KConfigFuzz/static/mssa2syscall/build/lib/CompactOutput.json"
    FianlOutputfileName = 'finalOutput.txt'

    srcLine2idx = {}
    idx2syscalls = {}
    rawItems = LoadJson(StaticAnalysisfileName)
    for item in rawItems:
        if item["target syscall infos"] == []:
            continue
        idx = item["case index"]
        source = item["source"]
        line = item["line"]
        if srcLine2idx.get(source) is None:
            srcLine2idx[source] = {}
        if srcLine2idx[source].get(line) is None:
            srcLine2idx[source][str(line)] = idx
        idx2syscalls[idx] = item
    del rawItems

    dependent_syscalls = []

    for line in open(DependetOpsfileName, 'r'):
        line_split = line.strip().split(':')
        read_src, read_line, write_src, write_line = line_split[0], str(line_split[1]), line_split[2], str(line_split[3])
        if srcLine2idx.get(read_src) is None:
            continue
        if srcLine2idx[read_src].get(read_line) is None:
            continue
        if srcLine2idx.get(write_src) is None:
            continue
        if srcLine2idx[write_src].get(write_line) is None:
            continue
        read_idx = srcLine2idx[read_src][read_line]
        write_idx = srcLine2idx[write_src][write_line]

        dependent_target_syscall = {
            "Target": [ syscall["target syscall"] for syscall in idx2syscalls[read_idx]["target syscall infos"]],
            "Relate": [ syscall["target syscall"] for syscall in idx2syscalls[write_idx]["target syscall infos"]],
            "Source": read_src, # 注意这里记录的是读语句（默认是条件分支语句）的源码路径和行号
            "Line": int(read_line)
            # "Addr": 0,
        }
        dependent_syscalls.append(dependent_target_syscall)

    with open("syscallPair.json", 'w+') as f:
        json.dump(dependent_syscalls, f)
