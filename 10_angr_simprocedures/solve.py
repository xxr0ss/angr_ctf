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


class MyCheckEqualsProc(angr.SimProcedure):
    def run(self, to_check, check_len):
        cmp_str = b'ORSDDWXHZURJRBDH'
        
        to_check_str_addr = to_check
        to_check_str_len = check_len
        to_check_str = self.state.memory.load(to_check_str_addr, to_check_str_len)

        return claripy.If(
            to_check_str == cmp_str,
            claripy.BVV(1, 32),
            claripy.BVV(0, 32)
        )


project.hook_symbol("check_equals_ORSDDWXHZURJRBDH", MyCheckEqualsProc())

simgr = project.factory.simgr(initial_state)
simgr.explore(find=0x0804A981, avoid=0x0804A96F)

if simgr.found:
    print('found')
    state: angr.SimState = simgr.found[0]
    res = state.posix.dumps(sys.stdin.fileno())
    print(res)
else:
    raise Exception('Solution not found')

# MSWKNJNAVTTOZMRY