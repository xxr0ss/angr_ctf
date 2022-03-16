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

buffer0 = claripy.BVS('buffer0', 32)
buffer1 = claripy.BVS('buffer1', 32)

class MyScanfProc(angr.SimProcedure):
    def run(self, fmt, arg0, arg1):
        self.state.memory.store(arg0, buffer0, endness=project.arch.memory_endness)
        self.state.memory.store(arg1, buffer1, endness=project.arch.memory_endness)
        return 0


project.hook_symbol("__isoc99_scanf", MyScanfProc())

simgr = project.factory.simgr(initial_state)
simgr.explore(find=0x0804FC99, avoid=0x0804FC87)

if simgr.found:
    print('found')
    state: angr.SimState = simgr.found[0]
    res0 = state.solver.eval(buffer0)
    res1 = state.solver.eval(buffer1)
    print(res0, res1)
    
else:
    raise Exception('Solution not found')

# 1448564819 1398294103