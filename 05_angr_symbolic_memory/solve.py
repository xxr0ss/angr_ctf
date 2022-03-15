import angr
import sys
import claripy


"""
.text:080485DD                 sub     esp, 0Ch
.text:080485E0                 push    offset unk_A1BA1D8
.text:080485E5                 push    offset unk_A1BA1D0
.text:080485EA                 push    offset unk_A1BA1C8
.text:080485EF                 push    offset user_input
.text:080485F4                 push    offset a8s8s8s8s ; "%8s %8s %8s %8s"
.text:080485F9                 call    ___isoc99_scanf
.text:080485FE                 add     esp, 20h
.text:08048601                 mov     [ebp+var_C], 0
"""

project = angr.Project(sys.argv[1])

start_addr = 0x08048601

initial_state: angr.SimState = project.factory.blank_state(
    addr=start_addr, 
    add_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)


pwds = [claripy.BVS(f'pwd{i}', 64) for i in range(4)]
pwds_addrs = [0x0A1BA1C0, 0x0A1BA1C8, 0x0A1BA1D0, 0x0A1BA1D8]
for i in range(4):
    initial_state.memory.store(pwds_addrs[i], pwds[i])

simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x0804866A, avoid=0x08048658)

if simulation.found:
    state = simulation.found[0]
    res = []
    for i in range(4):
        res.append(state.solver.eval(pwds[i], cast_to=bytes))
    print(b' '.join(res).decode())
    
else:
    raise Exception('Solution not found')

# NAXTHGNR JVSFTPWE LMGAUHWC XMDCPALU