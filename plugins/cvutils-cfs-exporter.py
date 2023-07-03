#------------------------------------------------------------------------------
# IDA Plugin to get an offset (rva) at the cursor position.
# Copy the 'cvutils-getoffset.py' into plugins directory of IDA
#------------------------------------------------------------------------------

VERSION = '1.0.0'
__AUTHOR__ = 'cra0'

PLUGIN_NAME = "Export Function Signatures"
PLUGIN_HOTKEY = "Ctrl+Shift+E"


  
import os
import sys
import idc
import idaapi
import idautils
import ida_ua

import ida_ida
UA_MAXOP=ida_ida.UA_MAXOP

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




def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return cvutils_exportsigs()

class cvutils_exportsigs(idaapi.plugin_t):

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Export select function signatures."
    help = "Select functions right-click, click Export Signatures."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    #--------------------------------------------------------------------------
    # Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # initialize the menu actions our plugin will inject
        self._init_action_export_sigs()

        # initialize plugin hooks
        self._init_hooks()

        # done
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """

        # unhook our plugin hooks
        self._hooks.unhook()

        # unregister our actions & free their resources
        self._del_ACTION_EXPORT_SIGNATURES()


        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    #--------------------------------------------------------------------------
    # Plugin Hooks
    #--------------------------------------------------------------------------

    def _init_hooks(self):
        """
        Install plugin hooks into IDA.
        """
        self._hooks = Hooks()
        self._hooks.hook()

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_EXPORT_SIGNATURES  = "prefix:export_signatures"


    def _init_action_export_sigs(self):
        """
        Register the export sigs action with IDA.
        """   
        # If the action is already registered, unregister it first.
        if idaapi.unregister_action(self.ACTION_EXPORT_SIGNATURES):
            idaapi.msg("Warning: action was already registered, unregistering it first\n")
        
        vaction_desc = "Export Signatures"
        if (sys.version_info > (3, 0)):
            # Describe the action using python3 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_EXPORT_SIGNATURES,                              # The action name.
                "Export Signatures",                                        # The action text.
                IDACtxEntry(export_signatures_go),                          # The action handler.
                PLUGIN_HOTKEY,                                              # Optional: action shortcut
                vaction_desc,                                               # Optional: tooltip
                35                                                          # Icon
            )
        else:
            # Describe the action using python2 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_EXPORT_SIGNATURES,                          # The action name.
                "Export Signatures",                                    # The action text.
                IDACtxEntry(export_signatures_go),                      # The action handler.
                PLUGIN_HOTKEY,                                          # Optional: action shortcut
                vaction_desc,                                           # Optional: tooltip
                35                                                      # Icon
            )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"


    def _del_ACTION_EXPORT_SIGNATURES(self):
        """
        Delete the bulk prefix action from IDA.
        """
        idaapi.unregister_action(self.ACTION_EXPORT_SIGNATURES)




#------------------------------------------------------------------------------
# Plugin Hooks
#------------------------------------------------------------------------------

class Hooks(idaapi.UI_Hooks):

    def __init__(self):
        # Call the __init__ method of the superclass
        super(Hooks, self).__init__()

        # Get the IDA version
        major, minor = map(int, idaapi.get_kernel_version().split("."))
        self.idaver_74newer = (major == 7 and minor >= 4)
        
        # If the IDA version is less than 7.4, define finish_populating_tform_popup
        if not self.idaver_74newer:
            self.finish_populating_tform_popup = self._finish_populating_tform_popup

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        """
        A right click menu is about to be shown. (IDA 7.x)
        """
        inject_export_signatures_actions(widget, popup_handle, idaapi.get_widget_type(widget))
        return 0


    def _finish_populating_tform_popup(self, form, popup):
        """
        A right click menu is about to be shown. (IDA 6.x)
        """
        inject_export_signatures_actions(form, popup, idaapi.get_tform_type(form))
        return 0


#------------------------------------------------------------------------------
# Prefix Wrappers
#------------------------------------------------------------------------------

def inject_export_signatures_actions(widget, popup_handle, widget_type):
    if widget_type == idaapi.BWN_FUNCS:
        idaapi.attach_action_to_popup(
            widget,
            popup_handle,
            cvutils_exportsigs.ACTION_EXPORT_SIGNATURES,
            "Export Signatures",
            idaapi.SETMENU_APP
        )
    return 0

#------------------------------------------------------------------------------
# Get Screen linear address
#------------------------------------------------------------------------------
def get_screen_linear_address(): 
    if idaver_74newer:
        return idc.get_screen_ea()
    else:
        return idc.ScreenEA()

#------------------------------------------------------------------------------
# Export Functions
#------------------------------------------------------------------------------

def get_list_of_functions():
    '''
    Gets all functions list.
    '''

    functions_list = {}
    seg_ea = idc.get_segm_by_sel(idc.SEG_NORM)

    for func_ea in idautils.Functions(idc.get_segm_start(seg_ea),
                                      idc.get_segm_end(seg_ea)):
        function_name = idc.get_func_name(func_ea)
        functions_list[function_name] = func_ea

    return functions_list

def get_selected_funcs():
    import sip
    twidget = ida_kernwin.find_widget("Functions window")
    widget  = sip.wrapinstance(int(twidget), QtWidgets.QWidget)

    if not widget:
        idaapi.warning("Unable to find 'Functions window'")
        return []

    table = widget.findChild(QtWidgets.QTableView)

    selected_funcs = [str(s.data()) for s in table.selectionModel().selectedRows()]
    func_list = get_list_of_functions()
    selected_funcs_ea = [func_list[func_name] for func_name in selected_funcs if func_name in func_list]

    return selected_funcs_ea
    
def add_bytes_to_sig(sig, address, size):
    for i in range(size):
        sig.append("{:02X}".format(idaapi.get_byte(address + i)))

def add_white_spaces_to_sig(sig, size):
    for i in range(size):
        sig.append("?")

def get_current_opcode_size(instruction):
    for i in range(UA_MAXOP):
        if instruction.ops[i].type == ida_ua.o_void:
            return 0, i
        if instruction.ops[i].offb != 0:
            return instruction.ops[i].offb, i
    return 0, 0

def match_operands(instruction, operand, size):
    # Check for data reference
    if idaapi.get_first_dref_from(instruction.ea) != idaapi.BADADDR: 
        return False

    if idaapi.get_first_cref_from(instruction.ea) != idaapi.BADADDR: # Code reference
        return False

    return True

def add_ins_to_sig(instruction, sig):
    size, count = get_current_opcode_size(instruction)
    if size == 0:
        add_bytes_to_sig(sig, instruction.ea, instruction.size)
    else:
        add_bytes_to_sig(sig, instruction.ea, size)

    if match_operands(instruction, 0, size):
        add_bytes_to_sig(sig, instruction.ea + size, instruction.size - size)
    else:
        add_white_spaces_to_sig(sig, instruction.size - size)

def is_subOrAdd_instruction(insn):
    # Default bytes of those instructions
    opcode_sub = [0x48, 0x83, 0xEC]
    opcode_add = [0x48, 0x83, 0xC4]

    # Get the bytes of the instruction
    insn_bytes = ida_bytes.get_bytes(insn.ea, insn.size)

    # Convert the byte array to a list of integer byte values
    insn_byte_list = [b for b in insn_bytes]

    # Compare the first three bytes of the instruction with the opcode
    return insn_byte_list[:3] == opcode_sub or insn_byte_list[:3] == opcode_add
        

class SigMaker:
    def __init__(self):
        pass
   
    def make_sig_default(self, start, end):
        signature = []
        current_address = start

        if (end - start) < 5:
            print("Signature must be greater than 5 bytes")
            return ""

        while current_address <= end:
            instruction = ida_ua.insn_t()
            if ida_ua.decode_insn(instruction, current_address) == 0:
                break

            if instruction.size < 5:
                add_bytes_to_sig(signature, current_address, instruction.size)
            else:
                add_ins_to_sig(instruction, signature)

            current_address += instruction.size

        return " ".join(signature)
    
    def make_sig_smart(self, start, end):
        signature = []
        current_address = start

        if (end - start) < 5:
            print("Signature must be greater than 5 bytes")
            return ""

        while current_address <= end:
            instruction = ida_ua.insn_t()
            if ida_ua.decode_insn(instruction, current_address) == 0:
                break

            #handle sub,add
            if is_subOrAdd_instruction(instruction):
                add_bytes_to_sig(signature, current_address, instruction.size - 1)
                add_white_spaces_to_sig(signature, 1)
                current_address += instruction.size
                continue

            if instruction.size < 5:
                add_bytes_to_sig(signature, current_address, instruction.size)
            else:
                add_ins_to_sig(instruction, signature)

            current_address += instruction.size

        return " ".join(signature)

def GenerateSignature(ea):
    sig_maker = SigMaker()

    func = idaapi.get_func(ea)
    if func is None:
        print("No function at 0x%08x" % ea)
        return None

    start = func.start_ea
    end = func.end_ea

    signature = sig_maker.make_sig_default(start, end)

    return signature

def export_signatures_go():
    sig_maker = SigMaker()

    selected_funcs = get_selected_funcs()
    if not selected_funcs:
        print("No functions selected.")
        return

    # Prompt for the output file path
    filename = ida_kernwin.ask_file(1, "*.cfs", "Enter the name of the  file:")
    if not filename:
        print("No file selected.")
        return

    # Build sigs and export!
    count = 0
    with open(filename, "w") as file:
        for func_ea in selected_funcs:
            start = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
            end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
            func_name = idc.get_func_name(start)

            # We'll create a signature for the entire function
            sig = sig_maker.make_sig_default(start, end)

            if sig is None:
                print(f"Failed to make a signature for function {func_name} at {start:x}")
                continue

            # Write the signature to the file
            file.write(f"{count},\"{func_name}\",\"{sig}\"\n")
            count += 1

    print(f"Exported {count} function signatures to {filename}")
    idaapi.warning("Exported %i function signatures to %s \n" % (count, filename))


#------------------------------------------------------------------------------
# IDA ctxt
#------------------------------------------------------------------------------

class IDACtxEntry(idaapi.action_handler_t):

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
        
#------------------------------------------------------------------------------
# Utilities
#------------------------------------------------------------------------------

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "plugin"))

def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(PLUGIN_PATH, "resources", resource_name)
    

def setClipboardText(data):
    cb = QApplication.clipboard()
    cb.clear(mode=cb.Clipboard )
    cb.setText(data, mode=cb.Clipboard)