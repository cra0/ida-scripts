#------------------------------------------------------------------------------
# IDA Plugin to jump to an offset from the Imagebase.
# Copy the 'cvutils-getoffset.py' into the plugins directory of IDA
#------------------------------------------------------------------------------

VERSION = '1.1.0'
__AUTHOR__ = 'cra0'

PLUGIN_NAME = "Go To Offset"
PLUGIN_HOTKEY = "Shift+G"


  
import os
import sys
import idc
import idaapi
import idautils
import string


major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

idaver_74newer = (major == 7 and minor >= 4)
idaver_8newer = (major >= 8)

if idaver_74newer or idaver_8newer:
    newer_version_compatible = True
else:
    newer_version_compatible = False

if newer_version_compatible:
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
    return cvutils_gotooffset()

class cvutils_gotooffset(idaapi.plugin_t):

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Go to an offset."
    help = "Use the shortcut key to open the goto dialog box."
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
        self._init_action_goto_offset()

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


        # unregister our actions & free their resources
        self._del_action_goto_offset()


        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)


    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_GET_OFFSET  = "prefix:goto_offset"


    def _init_action_goto_offset(self):
        """
        Register the copy bytes action with IDA.
        """   
        vaction_desc = "Go to offset."
        if (sys.version_info > (3, 0)):
            # Describe the action using python3 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_GET_OFFSET,                                     # The action name.
                "Go to offset",                                             # The action text.
                IDACtxEntry(goto_offset),                                # The action handler.
                PLUGIN_HOTKEY,                                              # Optional: action shortcut
                vaction_desc,                                               # Optional: tooltip
                31                                                          # Copy icon
            )
        else:
            # Describe the action using python2 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_GET_OFFSET,                                 # The action name.
                "Go to offset",                                         # The action text.
                IDACtxEntry(goto_offset),                            # The action handler.
                PLUGIN_HOTKEY,                                          # Optional: action shortcut
                vaction_desc,                                           # Optional: tooltip
                31                                                      # Copy icon
            )


        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"


    def _del_action_goto_offset(self):
        """
        Delete the bulk prefix action from IDA.
        """
        idaapi.unregister_action(self.ACTION_GET_OFFSET)

#------------------------------------------------------------------------------
# Display a warning message box
#------------------------------------------------------------------------------
def display_warning(message): 
    if newer_version_compatible:
        return idaapi.warning(message)
    else:
        return idc.Warning(message)
   
#------------------------------------------------------------------------------
# Jump to a certain address
#------------------------------------------------------------------------------
def jump_to_address(jump_address): 
    if newer_version_compatible:
        ida_kernwin.jumpto(jump_address)
    else:
        idc.Jump(jump_address)


#------------------------------------------------------------------------------
# Image Min EA
#------------------------------------------------------------------------------
def get_minEA(): 
    if newer_version_compatible:
        return ida_ida.inf_get_min_ea()
    else:
        return idc.MinEA()

#------------------------------------------------------------------------------
# IsBadAddress
#------------------------------------------------------------------------------

def is_hex(s):
     hex_digits = set(string.hexdigits)
     # if s is long, then it is faster to check against a set
     return all(c in hex_digits for c in s)

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def isvalid_address(ea):
    """Check if the given address is valid
    
    Arguments:
        ea: The linear address to check.
    """   
    if (ea == idaapi.BADADDR):
        print("[%x] BADADDR" % ea)
        return 0
        
    pe_min_ea = get_minEA()
       
    if (ea < pe_min_ea):
        print("[%x] is lower than MinEA [%x]" % (ea, pe_min_ea))
        return 0
               
    if not idaapi.getseg(ea):
        print("[%x] getseg failed" % ea)
        return 0
    
    return 1


#------------------------------------------------------------------------------
# Go to offset
#------------------------------------------------------------------------------

def goto_offset():
    hint_min_offset = get_minEA() - idaapi.get_imagebase()
    
    #Use string for now, force them to use hex as the offset
    offset_value=None
    if newer_version_compatible:
        offset_value = ida_kernwin.ask_str("0x%x" % hint_min_offset, 0, "To Offset[HEX]:")    
    else:
        offset_value = idc.AskStr("0x%x" % hint_min_offset, "To Offset[HEX]:")

    if not offset_value:
        print("No value was provided. Ignoring")
        return
    
    if not is_hex(offset_value):
        print("Bad input; It doesn't contain valid hex")
        display_warning("Bad Input!")
        return
        
    offset_hex = int(offset_value, 16)
    if offset_hex == 0:
        display_warning("Input is Invalid!")
        return
       
    image_base = idaapi.get_imagebase()
    jump_address = image_base + offset_hex
    
    if (isvalid_address(jump_address)):
        print ("Offset [%x] =-> Address [0x%x]" % (offset_hex, jump_address))
        jump_to_address(jump_address)
    else:
        display_warning("Bad Offset!")
    
    return

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