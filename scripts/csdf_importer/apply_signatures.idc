// apply_signatures.idc : CSDF Signature Definition Importer
// cra0 (cra0.net)
// https://github.com/cra0/ida-scripts/tree/master/scripts/csdf_importer

#include <idc.idc>

static getDirectoryPath(filePath)
{
	auto str = filePath;
	auto i = strstr(str, "\\");
	auto j = i + 1;
	while (i != -1)
	{
		str = str[i+1:];
		j = j + (i+1);
		i = strstr(str, "\\");
	}
	auto path = substr(filePath, 0, j - 3);
	return path;
}

static getFileName(filePath)
{
	auto str = filePath;
	auto i = strstr(str, "\\");
	while (i != -1)
	{
		str = str[i+1:];
		i = strstr(str, "\\");
	}
	return str;
}

static processSignatures(sigFileName, logFileName)
{
    auto fhSigFile, fhLog;
	auto line;
	auto funcCount = 0;
	auto counter = 0;
	auto resolved_count = 0;
	auto errorCount = 0;
	auto peBaseAddress = SegStart(MinEA());
	auto strFmtStr;

	auto logFilePath = getDirectoryPath(sigFileName) + logFileName;
	fhLog = fopen(logFilePath,"w");
	fprintf(fhLog,"----- PROCESS LOG ----- \n");
	
	
	fhSigFile = fopen(sigFileName,"r");	
	while((line = readstr(fhSigFile)) != -1)
	{
		if (strlen(line) <= 1)
			continue;
			
		if (line == '\n')//skip new line
			continue;
			
		if (substr(line, 0, 2)=="//")//skip comments
			continue;		
			
		if (funcCount == 0 && substr(line, 0, 2)=="-c")//skip comments
		{
			auto fcr = substr(line, 2, -1);
			funcCount = atol(fcr);
			fprintf(fhLog,"Function Count: %u\n", funcCount);
			fprintf(fhLog,"\n");
			
			Message("Function Count: %u \n", funcCount);
			continue;
		}
		
		//Address Offset
		auto stknDiv1 = strstr(line, ",");
		auto addressOf = substr(line, 0, stknDiv1);
		auto fAddressOffset = xtol(addressOf);		
		
		//Mangled Name
		auto strTok2 = substr(line, stknDiv1 + 2, -1);	
		auto stknDiv2 = strstr(strTok2, ",");		
		auto funcMangledName = substr(strTok2, 0, stknDiv2 - 1);
		
		//Display Name
		auto strTok3 = substr(strTok2, stknDiv2 + 2, -1);		
		auto stknDiv3 = strstr(strTok3, "\"");	
		auto funcName = substr(strTok3, 0, stknDiv3);
		
		
		auto funcAddress = peBaseAddress + fAddressOffset;
		
		strFmtStr = "(%u/%u) [%x] [%s] ==>";
		fprintf(fhLog, strFmtStr, resolved_count, funcCount, funcAddress, funcName);
		Message(strFmtStr, resolved_count, funcCount, funcAddress, funcName);	
		
		if (Qword(funcAddress) != BADADDR)
		{
			auto funcNameStr = GetFunctionName(funcAddress);
			auto funcNameStrRaw = Demangle(funcNameStr, GetLongPrm(INF_SHORT_DN));
			auto funcPrintName = funcNameStrRaw != 0 ? funcNameStrRaw : funcNameStr;

			if (GetFunctionFlags(funcAddress) == -1)
			{
				//Message("(%x is not a function! Making..)", funcAddress);
				MakeUnkn(funcAddress, 1);
				MakeCode(funcAddress);
				MakeFunction(funcAddress, BADADDR);
				MakeNameEx(funcAddress, funcMangledName, SN_NOWARN);
				MakeComm(funcAddress, "AUTO-GENERATED " + funcName);
				resolved_count++;
				strFmtStr = "[RESOLVED] %s\n";
				fprintf(fhLog, strFmtStr, funcMangledName);
				Message(strFmtStr, funcMangledName);
			}
			else if (funcNameStr != 0 && strlen(funcNameStr) >= 3)
			{
				if (funcNameStr[0:3] == "sub")
				{
					MakeNameEx(funcAddress, funcMangledName, SN_NOWARN);
					MakeComm(funcAddress, "AUTO-GENERATED " + funcName);
					resolved_count++;
					strFmtStr = "[RENAMED+RESOLVED] [%s] TO [%s]\n";
					fprintf(fhLog, strFmtStr, funcNameStr, funcMangledName);
					Message(strFmtStr, funcNameStr, funcMangledName);
				}
				else
				{			
					strFmtStr = "[IGNORED] Function @ 0x%x seems named.\n";
					fprintf(fhLog, strFmtStr, funcAddress);
					Message(strFmtStr, funcAddress);
				}
			}
			else
			{
				strFmtStr = "[UNKNOWN ERROR]\n";
				fprintf(fhLog, strFmtStr);
				Message(strFmtStr);
			}
			
		}
		else
		{
			errorCount++;
			strFmtStr = "[BAD!!!] Unable to resolve => %s @ [0x%x]  \n";
			fprintf(fhLog, strFmtStr, funcName, funcAddress);
			Message(strFmtStr, funcName, funcAddress);
		}

		counter++;
	}
	fprintf(fhLog,"\n");
	fprintf(fhLog,"Resolved: (%u/%u) Functions!\n", resolved_count, funcCount);
	fprintf(fhLog,"----- PROCESS LOG ----- \n");
	fclose(fhSigFile);	
	fclose(fhLog);
	
	Message("------------------------------------------ \n");
	Warning("Resolved (%u/%u) Functions!", resolved_count, funcCount);
	if (errorCount > 0 )
	{
		Warning(" Errors (%u) ", errorCount);
	}	
	
}


static main()
{
	Message("------------------------------------------ \n");
	Message("IDA Signature Resolver - cra0 (cra0.net) \n");  
	
	auto inputFilePath;
	
	inputFilePath = AskFile(0,"*.csdf","Cra0 Signature Definition File");
	if (inputFilePath != 0)
	{
		Message("Parsing: %s \n", inputFilePath);
		SetStatus(IDA_STATUS_WORK);
		processSignatures(inputFilePath, "csdf_import.log");
		SetStatus(IDA_STATUS_READY);
	}
	
	
}