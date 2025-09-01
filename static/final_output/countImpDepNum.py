import json

data = {}
deps = set()

with open("syscallPair_final2.json", 'r') as f:
    data = json.load(f)

for dep in data:
    for target in dep["Target"]:
        for relate in dep["Relate"]:
            deps.add((target, relate))
print(len(deps))