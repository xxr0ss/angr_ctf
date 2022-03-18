import angr
import sys
import claripy

base = 0x4000000
project = angr.Project(sys.argv[1], load_options={
    'main_opts': {
        'base_addr': base
    }
})

ptr_buffer = claripy.BVV(0x2000000, 32)
buffer = claripy.BVS('pwd', 8 * 8)

validation_func_offset = base + 0x6D7
initial_state = project.factory.call_state(
    validation_func_offset,
    ptr_buffer,
    claripy.BVV(8, 32),
    add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)
initial_state.memory.store(ptr_buffer, buffer)

simgr = project.factory.simgr(initial_state)

check_result_addr = base + 0x0775
simgr.explore(find=check_result_addr)

if simgr.found:
    state = simgr.found[0]
    state.add_constraints(state.regs.eax != 0)
    solution = state.solver.eval(buffer, cast_to=bytes)
    print(solution)
else:
    raise Exception('Solution not found')

# NMCFRIHK