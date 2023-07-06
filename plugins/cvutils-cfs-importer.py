#------------------------------------------------------------------------------
# IDA Plugin that imports CFS files
# Copy the 'cvutils-cfs-importer.py' into the plugins directory of IDA
#------------------------------------------------------------------------------

VERSION = '1.0.0'
__AUTHOR__ = 'cra0'

PLUGIN_NAME = "CFS Importer"
PLUGIN_HOTKEY = "Ctrl+Shift+I"


import os
import idc
import idaapi

import ida_bytes
import ida_funcs
import ida_name

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

idaver_74newer = (major == 7 and minor >= 4)

if idaver_74newer:
    #IDA 7.4+
    #https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
    import ida_ida
    import ida_kernwin

if using_pyqt5:
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets
    from PyQt5.Qt import QApplication

else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore
    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    from PySide.QtGui import QApplication
    
 
class ImportFileMenuHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def get_directory_path(self, file_path):
        """
        Get the directory path from a given file path.
        """
        return os.path.dirname(file_path)

    def get_file_name(self, file_path):
        """
        Get the file name from a given file path.
        """
        return os.path.basename(file_path)

    def find_all_matches(self, min_ea, max_ea, signature, max_matches=-1):
        matches = []
        ea = idaapi.find_binary(min_ea, max_ea, signature, 16, idaapi.SEARCH_DOWN)
        count = 0

        while ea != idaapi.BADADDR:
            matches.append(ea)
            count += 1
            if max_matches != -1 and count >= max_matches:
                break
            ea = idaapi.find_binary(ea + 1, max_ea, signature, 16, idaapi.SEARCH_DOWN)

        return matches
       
    def process_signatures(self, sig_file_path):
        """
        Process the signatures and resolve function names in IDA.
        """
        counter = 0
        resolved_count = 0
        error_count = 0
        min_ea = idaapi.cvar.inf.min_ea
        max_ea = idaapi.cvar.inf.max_ea
        is_64bit = idc.__EA64__

        print("Processing Signatures...")

        with open(sig_file_path, "r") as sig_file:
            for line in sig_file:
                line = line.strip()

                if not line or line.startswith("//"):
                    continue

                # Index
                index, line = line.split(",", 1)
                index = int(index)

                # Function Name
                func_name, line = line.split(",", 1)
                func_name = func_name.strip()

                # Signature
                signature = line.strip()[1:-1]  # Remove surrounding quotes


                # Find all matches
                ea = idaapi.BADADDR
                matches = self.find_all_matches(min_ea, max_ea, signature, 2)
                matches_count = len(matches)
                if matches_count > 1:
                    print("Multiple signature matches[%i] found for [%s] ignoring sig." % (matches_count, func_name))
                    continue

                # Set EA if we have only 1 hit, change this if you wish.
                if matches_count == 1:
                    ea = matches[0]

                print(f"({resolved_count}/{counter}) [{ea:X}] [{func_name}] ==> ", end="")

                if ea != idaapi.BADADDR:
                    if ida_bytes.get_full_flags(ea) != idaapi.BADADDR:
                        func_name_str = ida_name.get_name(ea)
                        func_name_str_raw = idc.demangle_name(func_name_str, idc.get_inf_attr(idc.INF_SHORT_DN))
                        func_print_name = func_name_str_raw if func_name_str_raw else func_name_str

                        if idc.get_func_flags(ea) == -1:
                            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1)
                            idc.create_insn(ea)
                            ida_funcs.add_func(ea)
                            ida_name.set_name(ea, func_name, ida_name.SN_FORCE)
                            idc.set_cmt(ea, "SIG-RESOLVED " + func_name, 1)
                            resolved_count += 1
                            print("[RESOLVED]")
                        elif func_name_str and len(func_name_str) >= 3:
                            if func_name_str[:3] == "sub":
                                ida_name.set_name(ea, func_name, ida_name.SN_FORCE)
                                idc.set_cmt(ea, "SIG-RESOLVED " + func_name, 1)
                                resolved_count += 1
                                print("[RENAMED+RESOLVED]", func_name_str, "TO", func_name)
                            else:
                                print("[IGNORED] Function @ 0x{:X} seems named.".format(ea))
                        else:
                            print("[UNKNOWN ERROR]")
                    else:
                        error_count += 1
                        print("[BAD!!!] Unable to resolve =>", func_name, "@ [0x{:X}]".format(ea))
                else:
                    print("[NOT FOUND] Signature not found in the binary")

                counter += 1

        print("------------------------------------------")
        print("Resolved ({}/{}) Functions!".format(resolved_count, counter))
        if error_count > 0:
            print("Errors ({})".format(error_count))
            return False
         
        return True

    def main(self):
        sig_file_path = ida_kernwin.ask_file(0, "*.cfs", "Cra0 Signature Definition File")
        if sig_file_path:
            print("------------------------------------------")
            print("IDA Signature Resolver - cra0 (cra0.net)")
            print("Parsing:", sig_file_path)
            
            # Show the "Please wait" dialog before starting the heavy sigfind operation
            idaapi.show_wait_box("Processing... Please Wait (This may take a while chill)")
            
            if not self.process_signatures(sig_file_path):
               idaapi.warning("Some errors occurred while importing.") 

            # Hide the "Please wait" dialog
            idaapi.hide_wait_box()


    # Invoke the main
    def activate(self, ctx):
        self.main()  # call the main function when the action is activated
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class CFSImportPlugin(idaapi.plugin_t):
    flags = 0
    comment = "CFS Importer Plugin"
    help = "Import a CFS File into your idb."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    ACTION_IMPORT_SIGNATURES  = "cfs:import_action"
    ACTION_TOOLTIP_ICON = 198

    def init(self):
        # Create a new action
        action_desc = idaapi.action_desc_t(
            self.ACTION_IMPORT_SIGNATURES,   # The action name.
            'CFS File...',  # The action text.
            ImportFileMenuHandler(),  # The action handler.
            PLUGIN_HOTKEY,   # Optional: the action shortcut.
            'Import a CFS File into the current idb.',  # Optional: the action tooltip.
            self.ACTION_TOOLTIP_ICON)   # Icon.

        # Register the action
        idaapi.register_action(action_desc)

        # Attach the action to a menu item in the File menu.
        idaapi.attach_action_to_menu('File/Load file/',   # The relative path of where to add the action.
                                      self.ACTION_IMPORT_SIGNATURES,   # The action ID (declared above).
                                      idaapi.SETMENU_APP)   # We want to append the action after.

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("CFSImportPlugin is running")

    def term(self):
        idaapi.unregister_action(self.ACTION_IMPORT_SIGNATURES)


def PLUGIN_ENTRY():
    return CFSImportPlugin()