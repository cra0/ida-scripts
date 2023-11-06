# fix_dump_x64.py : A very crude attempt at fixing a packed dump
# cra0 (cra0.net)
# https://github.com/cra0/ida-scripts/tree/master/scripts/theia-packer-dump-fixer/fix_dump_x64.py

import idc
import idaapi
import ida_bytes
import ida_funcs
import ida_name


def get_length(ea):
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

def identify_functions():
    """
    Identify functions based on the custom padding.
    """
    min_ea = idaapi.cvar.inf.min_ea
    max_ea = idaapi.cvar.inf.max_ea

    ea = min_ea
    function_count = 0

    while ea < max_ea:

        # Check Segment is executable
        if not is_executable_segment(ea):
            segment_end = get_segment_end(ea)
            if segment_end != -1:
                ea = segment_end
                continue
            else:
                #print(f"Unable to get segment end @ 0x{ea:x}")
                ea += 1
                continue

        #print(f"We begin @ 0x{ea:x}")
        #break
  
        # Check if the instruction is already defined as code and can be disassembled   
        insn = idaapi.insn_t()
        if (idaapi.decode_insn(insn, ea) > 0):
            if insn.itype not in [idaapi.NN_jmp, idaapi.NN_retn, idaapi.NN_retf]:
                #move on
                ea += insn.size
                continue
            else:
                #found jmp or ret, move the IP to the end
                ea += insn.size
        else:
            #print(f"Failed to decode instruction at 0x{ea:x}")
            # If unable to decode, use idaapi.find_binary to find the next occurrence of 'F1'
            ea = idaapi.find_binary(ea, max_ea, "F1", 16, idaapi.SEARCH_DOWN)
            if ea == idaapi.BADADDR:
                print("No more occurrences of 'F1' found, exiting.")
                ea+= 1
                continue
        
        
        if not is_executable_segment(ea):
                    segment_end = get_segment_end(ea)
                    if segment_end != -1:
                        ea = segment_end
                        continue
                    else:
                        ea += 1
                        continue       
        
        
        #print(f"Found @ 0x{ea:x}")     
   
        # Check if the next byte is 'F1', if not, continue searching
        if ida_bytes.get_byte(ea) != 0xF1:
            ea += 1
            continue
        
        # Find the next byte that is not 'F1' (icebp)
        while ida_bytes.get_byte(ea) == 0xF1:
            ea += 1
            
       # Ensure the address is 8-byte aligned before making a function
        if ea % 8 != 0:
            # Not aligned, so skip to the next aligned address
            ea += 8 - (ea % 8)
            continue
            
            
        #print(f"Function start: 0x{ea:x}")    
        if ea < max_ea:   
        
            # Check if this function has already been resolved
            existing_comment = idc.get_cmt(ea, 1)
            if existing_comment == "FUNCTION_RESOLVED":
                #print("[IGNORED] Function @ 0x{:X} seems processed!".format(ea))  
                ea += 1
                continue
                
            # Check if this is an existing function
            func_name_str = ida_name.get_name(ea)
            if func_name_str and len(func_name_str) >= 3:
                if func_name_str[:3] == "sub":
                    #print("[IGNORED] Function @ 0x{:X} seems named.".format(ea))                
                    ea += 1
                    continue  

            # Convert to code and define as function
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1)
            idc.create_insn(ea)
            new_func = ida_funcs.add_func(ea)
            function_count += 1  # Increment the counter
            
            # Rename the function
            func_name = "prc_" + hex(ea)[2:].upper()
            ida_name.set_name(ea, func_name, ida_name.SN_FORCE)

            # Add a comment to indicate that this function was resolved
            idc.set_cmt(ea, "FUNCTION_RESOLVED", 1)

            print(f"Defined function at 0x{ea:x} with name {func_name}")
            
            # Jump to the end of this function to continue the search
            func_obj = ida_funcs.get_func(ea)
            if func_obj:
                ea = func_obj.end_ea
            else:
                print(f"Failed to get function object for 0x{ea:x}, continuing from next address.")
                ea += 1

    return function_count  # Return the count of identified functions


def main():
    """
    Main function.
    """
    idaapi.process_ui_action("msglist:Clear")
    print("Starting to identify functions...")
    count = identify_functions()
    print(f"Identified and fixed {count} functions.")

if __name__ == "__main__":
    main()
