# 序言
KConfigFuzz可分为四个部分，其中前三个部分为静态分析部分，第四部分为动态执行部分：
- 第一部分：配置项信息提取，提取配置项管辖的各个代码范围，以及配置项之间的关系。
- 第二部分：读写依赖对提取，利用SVF对内核的bitcode(.bc)文件进行mssa解析，获取读写依赖对。
- 第三部分：系统调用分析。获取调用这些读写依赖对的系统调用，从而构建系统调用间的隐式依赖关系。
- 第四部分：模糊测试器。我们同时准备了Syzkaller和HEALER的两个版本，但是为了测试，我们推荐使用HEALER的版本。
# 分析前的准备
## 准备所需的工具链
```
mkdir tools
cd tools
# LLVM
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.1/clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz
tar -xf clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz
export LLVM_DIR=path/to/llvm-13
export PATH=$LLVM_DIR/bin:$PATH
export LD_LIBRARY_PATH=$LLVM_DIR/lib:$LD_LIBRARY_PATH
# SVF
sudo apt update
sudo apt install build-essential cmake git python3 zlib1g-dev libtinfo-dev
git clone https://github.com/SVF-tools/SVF.git
cd SVF
# undertaker
# 我们提供了原生版的undertaker，其位于KConfigFuzz/static/config/original-undertaker-tailor目录下，按照如下方式构建之：
apt-get install libboost1.55-dev libboost-filesystem1.55-dev libboost-regex1.55-dev libboost-thread1.55-dev libboost-wave1.55-dev libpuma-dev libpstreams-dev check python-unittest2 clang sparse pylint
make
make install
# python3
pip install kconfiglib
```
## 准备Linux源码
建立一个tmp目录，这个目录负责存储Linux内核源码（这里使用的是6.2版）以及编译的.bc文件：   
```
mkdir tmp
git clone --depth 1 --branch v6.2 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux
```
# 第一部分
在执行脚本前，记得修改test_config.sh里面的Linux内核源码路径（这里写的是/home/jiakai/tmp/linux）：  
```
cd KConfigFuzz/config
./test_config.sh
```
由于捕获的是所有可能的内核配置项，因此该过程会耗费一段时间，结束后```KConfigFuzz/static/config```目录下会产生以下文件：  
- config_codeblock.json 配置项->管辖代码范围
- codeblock_config.json 上个文件的取反版，管辖代码范围->配置项
- config_tree.json 配置项->管辖的子配置项
- file_codeblock.json 中间文件，可以不用管
保存好以下几个文件，后面的分析过程中会用到。
# 第二部分
## 编译内核bitcode文件
修改KConfigFuzz/compile.sh文件的几个路径：   
```
SRC_DIR       # 内核源码目录（默认为tmp/linux）
OUTPUT_DIR    # .bc文件输出目录（默认为tmp/linux_bc_test）
CLANG_PATH    # clang编译器路径（默认为tools/clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04/bin/clang）
```
然后直接执行。该过程会生成内核源码的bitcode文件，存放于```OUTPUT_DIR```所指向的目录里。
```
./compile.sh
```
注：为了方便测试，编译内核使用的是默认配置项清单（make defconfig），可参见compile.sh的第49行。如果你有自己的配置项清单（即tmp/linux下有自己的.config），请修改此处。
## 生成内核镜像
```
cd tmp/linux
make -j$(nproc)
```
将KConfigFuzz/kernelobj2code.sh脚本放到tmp/linux下并执行，其会记录目标文件到源码文件的关系，生成一个叫```dependencies.yaml```的文件，请妥善保存该文件，后面会用到。
## 读写依赖对分析
```
cd KConfigFuzz/static/bc2mssa
```
修改```run-partition-analysis.py```的以下内容：
- 454行的路径。该路径指定了第一部分生成的config_codeblock.json的路径。
- 457行的路径。该路径指定了dependencies.yaml的路径。
修改后直接执行该python文件：
```
python3 run-partition-analysis.py
```
该脚本会生成两个文件——bcs_index.json和index_config.json。随后修改```partitioned_analysis.sh```的第15行路径，该路径指向.bc文件输出目录，然后执行它。注意：由于静态分析的时间复杂度很高，该脚本会执行很长的时间（1-2天），可以在该脚本执行的过程中完成第四部分的工作。最后该脚本会在当前目录下建立一个output目录，所有的分析结果存在该目录里。   
在该脚本执行结束后，修改```KConfigFuzz/static/mssa2line/process_mssa_files.sh```的以下三个路径：
- input_dir #上一步output目录的路径
- config_codeblock  #第一部分生成的config_codeblock.json的路径
- config_tree   #第一部分生成的config_tree.json的路径
修改```KConfigFuzz/static/mssa2line/config2code.py```的第48行为linux源码的<br>绝对路径</br>。   
然后执行该脚本：
```
cd KConfigFuzz/static/mssa2line
./process_mssa_files.sh
```
该脚本会在当前目录下生成大量result_related*.txt文件，里面存储的就是所有分析出来的读写依赖对。将这些依赖对去重后存到一个文件里：
```
find . -name "result_related*.txt" -type f -exec cat {} + | sort -u > merged_unique.txt
python3 tmpParse.py
```
最终会生成一个叫dependent_ops.txt的文件，存储去重后的读写依赖对，请妥善保存该文件。
# 第三部分
## 分析插件编译
为了分析哪些系统调用可以触发这些读写依赖对，我们使用基于LLVM的分析插件，首先依次编译这两个插件：
```
cd KConfigFuzz/static/line2syscall/syzdirect_function_model
make
cd ../../mssa2syscall
make
```
先执行第一个插件。在执行前请留意```generate_syscall2src.py```的以下几行路径：
- 第480行，syz-features程序的路径。
- 第481行，前面编译的syzdirect_function_model插件的地址。
- 第510行，第二部分的.bc文件输出目录。
- 第511行，插件执行结果的输出目录。
确保路径无误后执行之。由于这个插件需要syzkaller下的syz-features分析系统调用信息，因此请确保您的syzkaller已成功编译（虽然我们提供了x86版的syz-features程序，可直接用，但其是否能正常运行取决于测试环境），有关如何编译syzkaller等模糊测试工具，请参见第四部分。
```
cd ../line2syscall
python3 generate_syscall2src.py
```
该插件会在输出目录下产生以下重要的文件：
- kernelCode2syscall.json 部分系统调用与部分内核函数间映射的记录。
- syzkaller_signature.txt 系统调用的签名文件。
然后执行第二个插件：
```
cd KConfigFuzz/static/mssa2syscall/build/lib
./target_analyzer -multi-pos-points=第二部分dependent_ops.txt路径 --verbose-level=4 -kernel-interface-file=kernelCode2syscall.json路径  .bc文件输出目录
```
该插件会输出CompactOutput.json，记录了能调用这些读写依赖的系统调用相关信息。
## 最后的准备工作
这些数据需要处理成测试器能利用的格式。   
执行下面的命令，调用Python即可。执行前请记得确认```KConfigFuzz/static/final_output/generate_output.py```的以下路径无误：
- 第166行，dependent_ops.txt的路径。
- 第167行，CompactOutput.json的地址。
```
cd KConfigFuzz/static/final_output
python3 generate_output.py
```
该文件最终会于本地生成一个syscallPair.json文件。   
然后依次执行：
```
python3 parseSyscallPair.py vmlinux_path syscallPair.json
python3 parseSyscallPair_and_0xffffffff.py
```
最后，本地会生成一个syscallPair_final2.json文件。这就是最终处理好的系统调用依赖对信息文件。
恭喜您！您已经成功生成了测试所需的所有信息！
# 第四部分
由于KConfigFuzz支持的两个测试器都需要qemu，因此请确保您的测试环境里已有QEMU虚拟机。
## Syzkaller的编译与使用
Syzkaller使用Go语言编写，因此需要确保您的测试环境里有Go：
```
# 下载最新 Go（以 go1.21.5.linux-amd64 为例）
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go  # 如果已存在
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# 添加到 PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```
然后就可以直接编译我们提供的Syzkaller了：
```
cd KConfigFuzz/fuzzers/syzkaller
make
```
成功后会在```bin```目录下看到多个可执行文件，其中会包含```syz-features```。  
Syzkaller支持自主启动虚拟机和SSH链接测试机两种方式，我们建议使用SSH链接测试机的方式，即先启动QEMU测试机，再让Syzkaller链接进行测试。在测试前，请将```syscallPair_final2.json```，```codeblock_config.json```，```config_tree.json```和内核镜像```vmlinux```存储到测试机上。测试的配置文件可参考如下模板：
```
{
        "target": "linux/amd64",
        "http": "127.0.0.1:56741",
        "rpc": "127.0.0.1:0",
        "sshkey" : "/home/jiakai/images/bullseye.id_rsa", // 虚拟机所用磁盘的密钥，应随着磁盘文件（.img）一并生成
        "workdir": "/home/jiakai/syzkaller/workdir", // 存储日志和种子的目录
        "kernel_obj": "/home/jiakai/linux", // 存放vmlinux的位置
        "syzkaller": "/home/jiakai/syzkaller", // 存放syzkaller的位置
        "sandbox": "setuid",
        "type": "isolated",
        "vm": {
                "targets" : [ "127.0.0.1:10021" ],
                "pstore": false,
                "target_dir" : "/home/fuzzdir",
                "target_reboot" : false
        }
}
```
## HEALER的编译
HEALER使用Rust语言编写。首先安装Rust：
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustc --version # check install
```
然后直接编译：
```
cargo build --release
```
关于如何构建工作目录和启动HEALER的方式，可参见<a>https://github.com/SunHao-0/healer/blob/main/README.md</a>，这里不再赘述。  
在测试前，将```syscallPair_final2.json```，```codeblock_config.json```，```config_tree.json```和内核镜像```vmlinux```一并放在工作目录下，然后就可以测试了。