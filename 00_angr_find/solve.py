import angr
import sys

project = angr.Project(sys.argv[1])

initial_state = project.factory.entry_state(
    add_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)

simulation = project.factory.simgr(initial_state)

simulation.explore(find=0x8048675)

if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())

else:
    raise Exception('Solution not found')

# JXWVXRKX