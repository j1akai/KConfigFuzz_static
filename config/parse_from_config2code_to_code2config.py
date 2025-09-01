import json, sys

source_src, dest_src = sys.argv[1], sys.argv[2]

data = {}
res = {}

with open(source_src, 'r') as f:
    data = json.load(f)

for config, codeblocks in data.items():
    for src, ranges in codeblocks.items():
        if res.get(src) is None:
            res[src] = {}
        for block in ranges:
            if block == [0]:
                blockrange = '0'
            else:
                blockrange = f"{block[0]}-{block[1]}"
            if res[src].get(blockrange) is None:
                res[src][blockrange] = []
            res[src][blockrange].append(config)

with open(dest_src, 'w') as f:
    json.dump(res, f)