import angr
import sys
import claripy

project = angr.Project(sys.argv[1])

"""
.text:08048682                 lea     eax, [ebp+var_10]
.text:08048685                 push    eax
.text:08048686                 lea     eax, [ebp+var_C]
.text:08048689                 push    eax
.text:0804868A                 push    offset aUU      ; "%u %u"
.text:0804868F                 call    ___isoc99_scanf
.text:08048694                 add     esp, 10h
.text:08048697                 mov     eax, [ebp+var_C]
"""

start_addr = 0x08048697
initial_state: angr.SimState = project.factory.blank_state(
    addr = start_addr,
    add_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)

# construct our own stack
initial_state.regs.ebp = initial_state.regs.esp

pwds = [claripy.BVS(f'pwd{i}', 32) for i in range(2)]

initial_state.regs.esp -= 8
initial_state.stack_push(pwds[0])
initial_state.stack_push(pwds[1])
# the rest of the instructions use ebp + offset, so we don't care about the esp

simulation = project.factory.simgr(initial_state)

def is_successful(state: angr.SimState):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good' in stdout_output

def should_abort(state: angr.SimState):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try' in stdout_output

simulation.explore(
    find=is_successful, avoid=should_abort
)

if simulation.found:
    state = simulation.found[0]
    solutions = [state.solver.eval(pwds[i]) for i in range(2)]
    print(*solutions)
else:
    raise Exception('Solution not found')