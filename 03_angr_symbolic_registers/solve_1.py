import angr
import sys
import struct

import claripy

project = angr.Project(sys.argv[1])

start_addr = 0x08048980 # after call    get_user_input
initial_state: angr.SimState = project.factory.blank_state(
    addr = start_addr,
    add_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)

pwds = [claripy.BVS(f'pwd{i}', 32) for i in range(3)]
initial_state.regs.eax = pwds[0]
initial_state.regs.ebx = pwds[1]
initial_state.regs.edx = pwds[2]

simulation = project.factory.simgr(initial_state)

def is_successful(state: angr.SimState):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good' in stdout_output

def should_abort(state: angr.SimState):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try' in stdout_output

simulation.explore(find=0x080489E6, avoid=0x080489D4)

if simulation.found:
    solution_state = simulation.found[0]
    solutions = [solution_state.solver.eval(pwds[i]) for i in range(3)]
    print(' '.join(['%x' % s for s in solutions]))

else:
    raise Exception('Solution not found')