echo "file_codeblock"
python3 undertakerParser.py file_codeblock /home/jiakai/tmp/linux ./file_codeblock.json

echo "config_codeblock"
python3 undertakerParser.py config_codeblock /home/jiakai/tmp/linux ./file_codeblock.json ./config_codeblock.json

echo "config_tree"
python3 configtree.py /home/jiakai/tmp/linux ./config_tree.json

echo "config_codeblock"
python3 parse_from_config2code_to_code2config.py ./config_codeblock.json ./codeblock_config.json