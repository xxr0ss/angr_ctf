import angr, claripy, sys


project = angr.Project(sys.argv[1])

start_addr = 0x080488D6 # after ignore_me

initial_state: angr.SimState = project.factory.blank_state(
    addr=start_addr,
    add_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)

filename = 'OJKSQYDP.txt'
pwd = claripy.BVS('pwd', 0x40 * 8)

pwd_file = angr.SimFile(filename, pwd)

initial_state.fs.insert(filename, pwd_file)

simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x80489AD, avoid=0x08048993)

if simulation.found:
    state = simulation.found[0]
    print(state.solver.eval(pwd, cast_to=bytes))
else:
    raise Exception('Solution not found')