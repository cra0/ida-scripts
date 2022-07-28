// apply_signatures.idc : CVDF VTable Definition Importer
// cra0 (cra0.net)
// https://github.com/cra0/ida-scripts/tree/master/scripts/cvdf_importer

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

static processVTables(defFileName, logFileName)
{
    auto fhDefFile, fhLog;
	auto logFilePath;
	auto line;
	auto vtblCount = 0;
	auto counter = 0;
	auto resolved_count = 0;
	auto errorCount = 0;
	auto peBaseAddress = SegStart(MinEA());
	auto strFmtStr;

	logFilePath = getDirectoryPath(defFileName) + logFileName;
	fhLog = fopen(logFilePath,"w");
	fprintf(fhLog,"----- PROCESS LOG ----- \n");
	
	
	fhDefFile = fopen(defFileName,"r");	
	while((line = readstr(fhDefFile)) != -1)
	{
		if (strlen(line) <= 1)
			continue;
			
		if (line == '\n')//skip new line
			continue;
			
		if (substr(line, 0, 2)=="//")//skip comments
			continue;		
			
		if (vtblCount == 0 && substr(line, 0, 2)=="-c")//skip comments
		{
			auto fcr = substr(line, 2, -1);
			vtblCount = atol(fcr);
			fprintf(fhLog,"VTable Count: %u\n", vtblCount);
			fprintf(fhLog,"\n");
			
			Message("VTable Count: %u \n", vtblCount);
			continue;
		}
		
		//Address Offset
		auto stknDiv1 = strstr(line, ",");
		auto addressOf = substr(line, 0, stknDiv1);
		auto fAddressOffset = xtol(addressOf);		
		
		//Name
		auto strTok2 = substr(line, stknDiv1 + 2, -1);	
		auto stknDiv2 = strstr(strTok2, ",");		
		auto vtblVarName = substr(strTok2, 0, stknDiv2 - 1);
		
		//Display Name
		auto strTok3 = substr(strTok2, stknDiv2 + 2, -1);		
		auto stknDiv3 = strstr(strTok3, "\"");	
		auto displayName = substr(strTok3, 0, stknDiv3);
		
		//Address
		auto vtblAddress = peBaseAddress + fAddressOffset;
		
		strFmtStr = "(%u/%u) [%x] [%s] ==>";
		fprintf(fhLog, strFmtStr, resolved_count, vtblCount, vtblAddress, vtblVarName);
		Message(strFmtStr, resolved_count, vtblCount, vtblAddress, vtblVarName);	
		
		if (Qword(vtblAddress) != BADADDR)
		{
			auto vtblNameStr = get_name(vtblAddress, GN_VISIBLE);
			auto vtblNameStrLen = strlen(vtblNameStr);
			
			if (vtblNameStrLen == 0)
			{
				MakeQword(vtblAddress);
				MakeName(vtblAddress, vtblVarName);
				MakeComm(vtblAddress, "AUTO-GENERATED " + displayName);
				resolved_count++;
				
				strFmtStr = "[CREATED] %x [%s]\n";
				fprintf(fhLog, strFmtStr, vtblAddress, displayName);
				Message(strFmtStr, vtblAddress, displayName);
			}
			else
			{
				if (vtblNameStrLen >= 3 && (vtblNameStr[0:3] == "unk" || vtblNameStr[0:3] == "off"))
				{
					strFmtStr = "[RENAMED] VTable @ 0x%x seems to exist. Renamed from [%s] to [%s]\n";
					fprintf(fhLog, strFmtStr, vtblAddress, vtblNameStr, vtblVarName);
					Message(strFmtStr, vtblAddress, vtblNameStr, vtblVarName);
					MakeQword(vtblAddress);
					MakeName(vtblAddress, vtblVarName);
					MakeComm(vtblAddress, "AUTO-GENERATED " + displayName);
					resolved_count++;
				}
				else
				{
					strFmtStr = "[IGNORED] Vtbl var already exists @ 0x%x as [%s]\n";
					fprintf(fhLog, strFmtStr, vtblAddress, vtblNameStr);
					Message(strFmtStr, vtblAddress, vtblNameStr);				
				}
			}
			
		}
		else
		{
			errorCount++;
			strFmtStr = "[BAD!!!] Unable to resolve => %s @ [0x%x]  \n";
			fprintf(fhLog, strFmtStr, vtblVarName, vtblAddress);
			Message(strFmtStr, vtblVarName, vtblAddress);
		}

		counter++;
	}
	fprintf(fhLog,"\n");
	fprintf(fhLog,"Resolved: (%u/%u) VTables!\n", resolved_count, vtblCount);
	fprintf(fhLog,"----- PROCESS LOG ----- \n");
	fclose(fhDefFile);	
	fclose(fhLog);
	
	Message("------------------------------------------ \n");
	Warning("Resolved (%u/%u) VTables!", resolved_count, vtblCount);
	if (errorCount > 0 )
	{
		Warning(" Errors (%u) ", errorCount);
	}	
	
}


static main()
{
	Message("------------------------------------------ \n");
	Message("IDA VTable Resolver - cra0 (cra0.net) \n");  
	
	auto inputFilePath;
	
	inputFilePath = AskFile(0,"*.cvdf","Cra0 VTable Definition File");
	if (inputFilePath != 0)
	{
		Message("Parsing: %s \n", inputFilePath);
		SetStatus(IDA_STATUS_WORK);
		Message("Path: %s \n", inputFilePath);
		processVTables(inputFilePath, "cvdf_import.log");
		SetStatus(IDA_STATUS_READY);
	}
	
	
}