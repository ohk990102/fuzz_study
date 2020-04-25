import angr
import claripy

FIND = [0x404FAB]
AVOID = []

def patch_and_anaylze():
    with open('./angrybird', 'rb') as f:
        buf = f.read()
    
    buf = bytearray(buf)
    for i in range(0x778, 0x781):
        buf[i] = 0x90
    
    for i in range(0x71A, 0x727):
        buf[i] = 0x90
    
    for i in range(0x750, 0x75E):
        buf[i] = 0x90
    
    buf[0x79D] = 0x8E
    buf[0x79D+1] = 0x50
    buf[0x79D+2] = 0x40

    buf[0x6060] = 21

    start = 0
    while True:
        start = buf.find(b'\xBF\x94\x50\x40\x00', start)
        if start == -1:
            break    
        AVOID.append(start + 0x400000)
        start += len(b'\xBF\x94\x50\x40\x00')

    with open('./angrybird_patch', 'wb') as f:
        f.write(buf)


if __name__ == "__main__":
    patch_and_anaylze()

    proj = angr.Project('./angrybird_patch', load_options={'auto_load_libs': False})
    flag = claripy.Concat(claripy.BVV(0, 8*(20)), claripy.BVV(b'\n'))
    state = proj.factory.blank_state(addr=0x4007B8)
    simgr = proj.factory.simulation_manager(state)
    print(AVOID)
    print(FIND)
    simgr.explore(find=FIND, avoid=AVOID)
    
    found = simgr.found[0]
    print(found.posix.dumps(0))
    print(found.state.posix.dumps(1))
