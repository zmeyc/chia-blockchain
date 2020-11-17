from src.types.program import Program
from clvm_tools import binutils


# nicked from stackoverflow
def diff(li1, li2):
    return (list(list(set(li1) - set(li2)) + list(set(li2) - set(li1))))


# Using readlines()
file = open('src/wallet/cc_wallet/blns.txt', 'r')
lines = [line for line in file.readlines() if line.strip()]

count = 0
breaking_lines_quotation = []
breaking_lines_apostrophe = []
breaking_lines_solution = []

# # Strips the newline character
# for line in Lines:
#     if line[0] != "#":
#         try:
#             prog = Program(binutils.assemble(f"(q \'{line}\')"))
#             cost_run, sexp = prog.run_with_cost([])
#             print("===================")
#             print(f"(q \'{line}\')")
#             print(cost_run)
#             print(sexp)
#             print("===================")
#         except Exception as e:
#             print(e)
#             breaking_lines_apostrophe.append(line)
#
# for line in Lines:
#     if line[0] != "#":
#         try:
#             prog = Program(binutils.assemble(f"(q \"{line}\")"))
#             cost_run, sexp = prog.run_with_cost([])
#             print("===================")
#             print(f"(q \"{line}\")")
#             print(cost_run)
#             print(sexp)
#             print("===================")
#         except Exception as e:
#             print(e)
#             breaking_lines_quotation.append(line)
for line in lines:
    if line[0] != "#":
        try:
            prog = Program(binutils.assemble(f"(c 2 (q ()))"))
            cost_run, sexp = prog.run_with_cost(Program.to([line.encode('utf-8')]))
            print(f"cost: {cost_run}")
            print(f"input: {line}")
            print(f"result: {sexp}")
            print(f"result dissasembled: {binutils.disassemble(sexp)}")
            print("===================")
        except Exception as e:
            print(e)
            breaking_lines_solution.append(line)
    else:
        print(line)
print("==================BREAKING STRINGS WHEN PASSED AS SOLUTION==============================")
print(breaking_lines_solution)
# print("==================BREAKING STRINGS APOSTROPHE=========================")
# print(breaking_lines_apostrophe)
# print("==================BREAKING STRINGS QUOTATION=========================")
# print(breaking_lines_quotation)
# print("==================BREAKING STRINGS DIFF=========================")
# print(diff(breaking_lines_quotation, breaking_lines_apostrophe))
