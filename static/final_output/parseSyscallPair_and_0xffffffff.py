import json

data = []
with open("syscallPair_new.json", 'r') as f:
    data = json.load(f)

for i in range(len(data)):
    item = data[i]
    targets, relates, addr = item["Target"], item["Relate"], item["Addr"]
    addr_value = int(addr, 16)
    addr_value = addr_value & 0xffffffff
    data[i]["Addr"] = addr_value

with open("syscallPair_final2.json", 'w+') as f:
    json.dump(data, f)
