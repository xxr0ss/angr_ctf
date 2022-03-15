import angr
import sys
import claripy


project = angr.Project(sys.argv[1])
initial_state = project.factory.entry_state(
    add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)

"""
.text:080486AE                 push    offset buffer
.text:080486B3                 call    check_equals_XYMKBKUHNIQYNQXE
.text:080486B8                 add     esp, 10h
"""

@project.hook(0x080486B3, length=5)
def skip_check_euqals(state: angr.SimState):
    buffer_addr = 0x0804A054
    buffer_len = 16

    input_string = state.memory.load(
        buffer_addr,
        buffer_len
    )

    state.regs.eax = claripy.If(
        input_string == b'XYMKBKUHNIQYNQXE',
        claripy.BVV(1, 32),
        claripy.BVV(0, 32)
    )

simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x08048765, avoid=0x08048753)

if simulation.found:
    state: angr.SimState = simulation.found[0]
    solution = state.posix.dumps(sys.stdin.fileno()).decode()
    print(solution)
else:
    raise Exception('Solution not found')

# ZXIDRXEORJOTFFJNWUFAOUBLOGLQCCGK