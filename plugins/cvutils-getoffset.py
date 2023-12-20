#------------------------------------------------------------------------------
# IDA Plugin to get an offset (rva) at the cursor position.
# Copy the 'cvutils-getoffset.py' into the plugins directory of IDA
#------------------------------------------------------------------------------

VERSION = '1.1.0'
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

idaver_74newer = (major == 7 and minor >= 4)
idaver_8newer = (major >= 8)

if idaver_74newer or idaver_8newer:
    is_version_compatible = True
else:
    is_version_compatible = False

if is_version_compatible:
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
        Register the get offset action with IDA.
        """   
        # If the action is already registered, unregister it first.
        if idaapi.unregister_action(self.ACTION_GET_OFFSET):
            idaapi.msg("Warning: action was already registered, unregistering it first\n")
        
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

    def __init__(self):
        # Call the __init__ method of the superclass
        super(Hooks, self).__init__()

        # Get the IDA version
        major, minor = map(int, idaapi.get_kernel_version().split("."))
        self.is_version_compatible = (major == 7 and minor >= 4)
        
        # If the IDA version is less than 7.4, define finish_populating_tform_popup
        if not self.is_version_compatible:
            self.finish_populating_tform_popup = self._finish_populating_tform_popup

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        """
        A right click menu is about to be shown. (IDA 7.x)
        """
        inject_address_offset_copy_actions(widget, popup_handle, idaapi.get_widget_type(widget))
        return 0


    def _finish_populating_tform_popup(self, form, popup):
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

def inject_address_offset_copy_actions(widget, popup_handle, widget_type):
    if widget_type == idaapi.BWN_DISASMS:
        idaapi.attach_action_to_popup(
            widget,
            popup_handle,
            cvutils_getoffset.ACTION_GET_OFFSET,
            "Get Address Offset",
            idaapi.SETMENU_APP
        )
    return 0

#------------------------------------------------------------------------------
# Get Screen linear address
#------------------------------------------------------------------------------
def get_screen_linear_address(): 
    if is_version_compatible:
        return idc.get_screen_ea()
    else:
        return idc.ScreenEA()


#------------------------------------------------------------------------------
# Get Offset
#------------------------------------------------------------------------------

def getcopy_offset():
    """
    Gets the offset of the current cursor's address
    """
    vImagebase = idaapi.get_imagebase()
    vCurrentPos = get_screen_linear_address()
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