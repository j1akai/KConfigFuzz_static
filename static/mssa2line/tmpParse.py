f = open("dependent_ops.txt", 'w+')

for line in open("merged_unique.txt", 'r'):
    line_split = line.strip().split()
    src1, line1, src2, line2 = line_split[0], int(line_split[1]), line_split[2], int(line_split[3])
    f.write(f"{src1}:{line1}:{src2}:{line2}\n")

f.close()