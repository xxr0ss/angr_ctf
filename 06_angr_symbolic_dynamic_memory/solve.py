import angr
import sys

import claripy


project = angr.Project(sys.argv[1])

start_addr = 0x08048699

initial_state: angr.SimState = project.factory.blank_state(addr=start_addr, add_options={
    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
})

fake_buf0 = 0x20000     # fake heap memory
fake_buf1 = 0x20010
ptr_buf0 = 0x0ABCC8A4
ptr_buf1 = 0x0ABCC8AC
pwds = [claripy.BVS(f'pwd{i}', 8*8) for i in range(2)]
initial_state.memory.store(fake_buf0, pwds[0])
initial_state.memory.store(fake_buf1, pwds[1])
initial_state.memory.store(ptr_buf0, fake_buf0, endness=project.arch.memory_endness, size=4)
initial_state.memory.store(ptr_buf1, fake_buf1, endness=project.arch.memory_endness, size=4)

simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x08048756, avoid=0x08048744)

if simulation.found:
    state: angr.SimState = simulation.found[0]
    print(b' '.join([state.solver.eval(pwds[i], cast_to=bytes) for i in range(2)]))
else:
    raise Exception('Solution not found')
