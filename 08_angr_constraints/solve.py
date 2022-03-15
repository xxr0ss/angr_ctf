import angr
import sys

import claripy


project = angr.Project(sys.argv[1])


"""
.text:08048613                 push    offset buffer
.text:08048618                 push    offset a16s     ; "%16s"
.text:0804861D                 call    ___isoc99_scanf
.text:08048622                 add     esp, 10h
.text:08048625                 mov     [ebp+var_C], 0
"""
start_addr = 0x08048625
initial_state: angr.SimState = project.factory.blank_state(
    addr = start_addr,
    add_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    }
)

buffer_addr = 0x0804A050
buffer = claripy.BVS('buffer', 0x11 * 8)
initial_state.memory.store(buffer_addr, buffer)

simulation = project.factory.simgr(initial_state)

"""
.text:08048669                 sub     esp, 8
.text:0804866C                 push    10h
.text:0804866E                 push    offset buffer
.text:08048673                 call    check_equals_AUPDNNPROEZRJWKB
.text:08048678                 add     esp, 10h
"""
addr_check_constraint = 0x08048669

simulation.explore(find=addr_check_constraint)
if simulation.found:
    state = simulation.found[0]

    check_param_addr = buffer_addr
    check_param_size_bytes = 0x10
    loaded_value = state.memory.load(
        check_param_addr,
        check_param_size_bytes
    )
    
    desired_value = b'AUPDNNPROEZRJWKB'
    state.add_constraints(loaded_value == desired_value)

    res = state.solver.eval(loaded_value, cast_to=bytes).decode()
    print(res)

else:
    raise Exception('Solution not found')

# AUPDNNPROEZRJWKB