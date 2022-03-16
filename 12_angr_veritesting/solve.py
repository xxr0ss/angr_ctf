import angr
import claripy
import sys


project = angr.Project(sys.argv[1])

initial_state = project.factory.entry_state(
    add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)

simgr = project.factory.simgr(initial_state, veritesting=True)
simgr.explore(find=0x08048679, avoid=0x0804868B)

if simgr.found:
    state = simgr.found[0]
    res = state.posix.dumps(sys.stdin.fileno())
    print(res)

else:
    raise Exception('Solution not found')

# OQSUWYACEGIKMOQSUWYACEGIKMOQSUWY