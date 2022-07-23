// vtbl_print.idc : An IDA IDC script that prints out a Virtual Method Table (VMT)
// at the current address your IDA cursor is at
// cra0 (cra0.net)
// https://github.com/cra0/ida-scripts/tree/master/scripts/misc/vtbl_print.idc


#include <idc.idc>

static main()
{
	//vars
	auto vtblFuncAddress;
	auto szFuncName, szFullName;
	auto vtblCounter = 0; //zero-based index
	
	SetStatus(IDA_STATUS_WORK);
  
	auto currentPtr = ScreenEA();
    if (currentPtr == BADADDR)
    {   
        Message("---| No valid vtable selected! Aborted Operation |---");                        
        SetStatus(IDA_STATUS_READY);
        return;
    }
	
	Message("\n"); 
	Message("VTBL : 0x%x \n", currentPtr); 
	Message("------------------------------------------ \n");  

    // Loop through the vtable block
    while (currentPtr != BADADDR)
    {
		vtblFuncAddress = Qword(currentPtr);          
        szFuncName = Name(vtblFuncAddress);
        if (strlen(szFuncName) == 0)
        {
            break;
        }
		
        szFullName = Demangle(szFuncName, GetLongPrm(INF_LONG_DN));
        if (szFullName == "")
            szFullName = szFuncName;

		Message("[%x] -> [%x] [%d] %s \n", currentPtr, vtblFuncAddress, vtblCounter, szFullName);               
        currentPtr = currentPtr + 8;
		vtblCounter++;
    };
	
	Message("------------------------------------------ \n");   
	SetStatus(IDA_STATUS_READY);
	return;
}
 