# resolve_unknown.py : An script that defines executable segments in your IDA project if they're unknown or set as data
# This is useful for when dealing with packer dumps
# cra0 (cra0.net)
# https://github.com/cra0/ida-scripts/tree/master/scripts/misc/resolve_unknown.py

import idc
import idaapi
import ida_bytes
import ida_funcs
import ida_name


def get_length(ea):
    """
    Get the length of the instruction at the given effective address.
    """
    insn = idaapi.insn_t()
    if (idaapi.decode_insn(insn, ea) > 0):
        return insn.size
    else:
        return 0

def is_executable_segment(ea):
    seg = idaapi.getseg(ea)
    if seg:
        return bool(seg.perm & idaapi.SEGPERM_EXEC)
    return False

def get_segment_end(ea):
    seg = idaapi.getseg(ea) 
    if seg:
        return seg.end_ea
    else:
        return -1


def define_unk_code():
    """
    Identify unk regions and turn them into code
    """
    min_ea = idaapi.cvar.inf.min_ea
    max_ea = idaapi.cvar.inf.max_ea

    # Define some progress breakpoints
    total_range = max_ea - min_ea
    num_intervals = 10  # Progress threshold
    progress_breakpoints = [min_ea + (total_range * i // num_intervals) for i in range(1, num_intervals)]

    ea = min_ea
    while ea < max_ea:

        # Show progress at breakpoints
        if ea in progress_breakpoints:
            print(f"Progress: Reached 0x{ea:x}")
            idc.jumpto(ea)
            
        # Check if EA is within a defined segment
        if idaapi.getseg(ea) is None:
            print(f"Found bad EA @ 0x{ea:x}") 
            break        

        # Check if segment is executable
        if not is_executable_segment(ea):
            segment_end = get_segment_end(ea)
            if segment_end != -1:
                ea = segment_end
                continue
            else:
                print(f"Unable to get segment end @ 0x{ea:x}")
                ea += 1
                continue

        # Try to create an instruction
        created = idc.create_insn(ea)
        if created:
            while ida_bytes.is_code(ida_bytes.get_flags(ea)) and ea < max_ea:
                if ea in progress_breakpoints:
                    print(f"Progress: Reached 0x{ea:x}")
                    idc.jumpto(ea)
                #print(f"EA 0x{ea:x}")
                ea += get_length(ea)
        else:
            ea += 1  # Move to the next byte

    return


def main():
    """
    Main function.
    """
    print("Starting to define executable as code...")
    print("Note this may take a while.\nPay attention to the Navigation Band at the top.")
    define_unk_code()
    print(f"Finished!")

if __name__ == "__main__":
    main()
