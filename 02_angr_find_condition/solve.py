import angr
import sys

project = angr.Project(sys.argv[1])
initial_state = project.factory.entry_state(
    add_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)

def successful(state: angr.SimState):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b"Good Job" in stdout_output

def should_abort(state: angr.SimState):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b"Try again" in stdout_output

simulation = project.factory.simgr(initial_state)
simulation.explore(
    find=successful,
    avoid=should_abort
)

if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
else:
    raise Exception('Solution not found')

# HETOBRCU