import angr
import sys


project = angr.Project(sys.argv[1])

project.hook_symbol('printf', angr.SIM_PROCEDURES['libc']['printf']())
project.hook_symbol('__isoc99_scanf', angr.SIM_PROCEDURES['libc']['scanf']())
project.hook_symbol('puts', angr.SIM_PROCEDURES['libc']['puts']())
project.hook_symbol('_strcmp', angr.SIM_PROCEDURES['libc']['strcmp']())
project.hook_symbol('__libc_start_main', angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

initial_state = project.factory.entry_state(
    add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)

simgr = project.factory.simgr(initial_state)

simgr.explore(find=0x80489D9, avoid=0x080489C7)

if simgr.found:
    state = simgr.found[0]
    res = state.posix.dumps(sys.stdin.fileno())
    print(res.decode())
else:
    raise Exception('Solution not found')

# PNMXNMUD