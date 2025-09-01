import json
import networkx as nx
import matplotlib.pyplot as plt

# 原始 JSON 数据
data = None
with open("syscallPair.json", 'r') as f:
    data = json.load(f)

# 创建有向图
G = nx.DiGraph()
edges = set()

for item in data:
    targets = item["Target"]
    if isinstance(targets, str):
        targets = [targets]
    elif not isinstance(targets, list):
        targets = [str(targets)]
    relates = set(str(r) for r in item["Relate"])
    for relate in relates:
        for target in targets:
            edge = (relate, str(target))
            if edge not in edges:
                edges.add(edge)
                G.add_edge(*edge)

# 尝试用 Graphviz sfdp 布局（如果没装 pygraphviz 会回退到 spring_layout）
try:
    pos = nx.nx_agraph.graphviz_layout(G, prog="sfdp")
except:
    pos = nx.spring_layout(G, k=1.5, iterations=200, seed=42)

# 绘制图形（不显示节点名字，节点小）
plt.figure(figsize=(10, 8))
nx.draw_networkx_nodes(G, pos, node_size=50, node_color='skyblue', alpha=0.8)
nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=8, alpha=0.5)

plt.axis('off')
plt.tight_layout()
plt.savefig("graph_sparse.png", dpi=300, bbox_inches='tight')