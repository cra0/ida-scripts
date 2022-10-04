#------------------------------------------------------------------------------
# IDA Plugin to get an offset (rva) at the cursor position.
# Copy the 'cvutils-getoffset.py' into plugins directory of IDA
#------------------------------------------------------------------------------

VERSION = '1.0.0'
__AUTHOR__ = 'cra0'

PLUGIN_NAME = "Get Address Offset"
PLUGIN_HOTKEY = "Ctrl+Shift+C"


  
import os
import sys
import idc
import idaapi
import idautils

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

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


def setClipboardText(data):
    cb = QApplication.clipboard()
    cb.clear(mode=cb.Clipboard )
    cb.setText(data, mode=cb.Clipboard)


def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return cvutils_getoffset()

class cvutils_getoffset(idaapi.plugin_t):

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Get the Adress offset at the cursor location."
    help = "At a certain location right-click 'Get Offset'"
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
        self._init_action_get_offset()

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
        self._del_action_get_offset()


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
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rrays hooks (when available).
        NOTE: This is called when the ui_ready_to_run event fires.
        """
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_GET_OFFSET  = "prefix:get_offset"


    def _init_action_get_offset(self):
        """
        Register the copy bytes action with IDA.
        """   
        vaction_desc = "Get the offset from the image base of the current cursor address."
        if (sys.version_info > (3, 0)):
            # Describe the action using python3 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_GET_OFFSET,                                     # The action name.
                "Get Offset",                                               # The action text.
                IDACtxEntry(getcopy_offset),                                # The action handler.
                PLUGIN_HOTKEY,                                              # Optional: action shortcut
                vaction_desc,                                               # Optional: tooltip
                31                                                          # Copy icon
            )
        else:
            # Describe the action using python2 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_GET_OFFSET,                                 # The action name.
                "Get Offset",                                           # The action text.
                IDACtxEntry(getcopy_offset),                            # The action handler.
                PLUGIN_HOTKEY,                                          # Optional: action shortcut
                vaction_desc,                                           # Optional: tooltip
                31                                                      # Copy icon
            )


        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"


    def _del_action_get_offset(self):
        """
        Delete the bulk prefix action from IDA.
        """
        idaapi.unregister_action(self.ACTION_GET_OFFSET)




#------------------------------------------------------------------------------
# Plugin Hooks
#------------------------------------------------------------------------------

class Hooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_address_offset_copy_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def finish_populating_tform_popup(self, form, popup):
        """
        A right click menu is about to be shown. (IDA 6.x)
        """
        inject_address_offset_copy_actions(form, popup, idaapi.get_tform_type(form))
        return 0

    def hxe_callback(self, event, *args):
        """
        HexRays event callback.
        """

        #
        # if the event callback indicates that this is a popup menu event
        # (in the hexrays window), we may want to install our prefix menu
        # actions depending on what the cursor right clicked.
        #

        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args

            idaapi.attach_action_to_popup(
                form,
                popup,
                cvutils_getoffset.ACTION_GET_OFFSET,
                "Get Address Offset",
                idaapi.SETMENU_APP,
            )

        # done
        return 0

#------------------------------------------------------------------------------
# Prefix Wrappers
#------------------------------------------------------------------------------

def inject_address_offset_copy_actions(form, popup, form_type):
    """
    Inject prefix actions to popup menu(s) based on context.
    """

    #
    # disassembly window
    #

    if form_type == idaapi.BWN_DISASMS:
        # insert the prefix action entry into the menu
        #

        idaapi.attach_action_to_popup(
            form,
            popup,
            cvutils_getoffset.ACTION_GET_OFFSET,
            "Get Address Offset",
            idaapi.SETMENU_APP
        )

    # done
    return 0

#------------------------------------------------------------------------------
# Get Offset
#------------------------------------------------------------------------------

def getcopy_offset():
    """
    Gets the offset of the current cursor's address
    """
    vImagebase = idaapi.get_imagebase()
    vCurrentPos = idc.get_screen_ea()
    if vCurrentPos != idaapi.BADADDR:
        vOffset = vCurrentPos - vImagebase
        print ("Address [0x%x] =-> Offset [%x] Copied to Clipboard!" % (vCurrentPos, vOffset))
        setClipboardText("%x" % vOffset)
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
        
#------------------------------------------------------------------------------
# Utilities
#------------------------------------------------------------------------------

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "plugin"))

def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(PLUGIN_PATH, "resources", resource_name)