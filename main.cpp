#include "stdafx.h"

int ShowErrorBox(HWND hWnd, HRESULT dwError, PCWSTR lpCaption, UINT uType)
{
	int r = 0;
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return 0;
		lpSource = ghnt;
	}

	PWSTR lpText;
	if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		r = MessageBox(hWnd, lpText, lpCaption, uType);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

void ShowDebugger(HANDLE hDebug)
{
	union {
		PSYSTEM_HANDLE_INFORMATION_EX pshi;
		PVOID buf;
	};

	NTSTATUS status;

	ULONG cb = 0x10000;
	do 
	{
		status = STATUS_NO_MEMORY;

		if (buf = new UCHAR[cb += 0x1000])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, cb, &cb)))
			{
				if (ULONG_PTR NumberOfHandles = pshi->NumberOfHandles)
				{
					ULONG_PTR MyProcessId = GetCurrentProcessId();

					PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles = pshi->Handles;
					do 
					{
						if (Handles->UniqueProcessId == MyProcessId &&
							Handles->HandleValue == (ULONG_PTR)hDebug)
						{
							PVOID Object = Handles->Object;

							Handles = pshi->Handles, NumberOfHandles = pshi->NumberOfHandles;

							do 
							{
								if (Handles->UniqueProcessId != MyProcessId &&
									Handles->Object == Object)
								{

									WCHAR sz[MAX_PATH];

									SYSTEM_PROCESS_ID_INFORMATION spid = { 
										(HANDLE)Handles->UniqueProcessId, { 0, sizeof(sz), sz }
									};

									if (0 > NtQuerySystemInformation(SystemProcessIdInformation, &spid, sizeof(spid), &cb))
									{
										swprintf_s(sz, _countof(sz), L"pid=[%x]", (ULONG)Handles->UniqueProcessId);
									}
									MessageBoxW(0, sz, L"Debugged by", MB_ICONWARNING);
								}

							} while (Handles++, --NumberOfHandles);

							break;
						}
					} while (Handles++, --NumberOfHandles);
				}
			}
			delete [] buf;
		}
	} while (STATUS_INFO_LENGTH_MISMATCH == status);
}

void DetachDebugger()
{
	HANDLE hDebug;
	NTSTATUS status = NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &hDebug, sizeof(HANDLE), 0);

	if (0 > status)
	{
		switch (status)
		{
		case STATUS_PORT_NOT_SET:
			break;
		default:
			ShowErrorBox(0, HRESULT_FROM_NT(status), L"Debugger not attached !", MB_ICONHAND);
		}
		return ;
	}

	ShowDebugger(hDebug);

	if (IDYES == MessageBoxW(0, L"Detach Debugger ?", L"Debugger Detected !", MB_ICONQUESTION|MB_YESNO))
	{
		BOOL KillOnExit = FALSE;
		NtSetInformationDebugObject(hDebug, DebugObjectKillProcessOnExitInformation, &KillOnExit, sizeof(KillOnExit), 0);

		ULONG op = MB_ICONINFORMATION;
		if (0 > (status = NtRemoveProcessDebug(NtCurrentProcess(), hDebug)))
		{
			op = MB_ICONHAND;
		}
		ShowErrorBox(0, 0 > status ? HRESULT_FROM_NT(status) : S_OK, L"NtRemoveProcessDebug", op);
	}

	NtClose(hDebug);
}

BOOL AreMappedFilesTheSame(PBYTE BaseAddress1, PBYTE BaseAddress2)
{
	if (NtAreMappedFilesTheSame(BaseAddress1, BaseAddress2))
	{
		return FALSE;
	}

	PIMAGE_NT_HEADERS pinth1 = RtlImageNtHeader(BaseAddress1);

	if (!pinth1 || pinth1->OptionalHeader.ImageBase != (ULONG_PTR)BaseAddress2)
	{
		return FALSE;
	}

	PIMAGE_NT_HEADERS pinth2 = RtlImageNtHeader(BaseAddress2);

	ULONG SizeOfHeaders = pinth1->OptionalHeader.SizeOfHeaders;

	if (SizeOfHeaders != pinth2->OptionalHeader.SizeOfHeaders)
	{
		return FALSE;
	}

	if (memcmp(pinth1, pinth2, SizeOfHeaders))
	{
		return FALSE;
	}

	BOOL bModify = FALSE;

	if (DWORD NumberOfSections = pinth1->FileHeader.NumberOfSections)
	{
		PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth1);

		do 
		{
			if (pish->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				if (DWORD VirtualSize = pish->Misc.VirtualSize)
				{
					DWORD VirtualAddress = pish->VirtualAddress;

					PVOID pv1 = BaseAddress1 + VirtualAddress, pv2 = BaseAddress2 + VirtualAddress;

					if (memcmp(pv1, pv2, VirtualSize))
					{
						bModify = TRUE;

						WCHAR sz[0x80];
						swprintf_s(sz, _countof(sz), L"Modify in %8S %08x +%08x", pish->Name, VirtualSize, VirtualAddress);
						MessageBoxW(0, sz, L"check ntdll", MB_ICONWARNING);

						ULONG op;
						if (VirtualProtect(pv2, VirtualSize, PAGE_EXECUTE_READWRITE, &op))
						{
							memcpy(pv2, pv1, VirtualSize);
							if (PAGE_EXECUTE_READWRITE != op) VirtualProtect(pv2, VirtualSize, op, &op);
						}
						else
						{
							return FALSE;
						}
					}
				}
			}
		} while (pish++, --NumberOfSections);
	}

	if (!bModify)
	{
		MessageBoxW(0, L"ntdll code not modified !", L"check ntdll", MB_ICONINFORMATION);
	}
	return TRUE;
}

struct RSM 
{
	PVOID pBaseAddress;
	ULONG dwProcessId, dwThreadId;
	WCHAR LibFileName[];
};

NTSTATUS OpenSection(_Out_ PHANDLE SectionHandle, _In_ PWSTR lpLibFileName)
{
	int len = 0;
	PWSTR buf = 0;

	while (0 < (len = _snwprintf(buf, len, L"\\KnownDlls\\%s", lpLibFileName)))
	{
		if (buf)
		{
			UNICODE_STRING ObjectName;
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
			RtlInitUnicodeString(&ObjectName, buf);

			return NtOpenSection(SectionHandle, SECTION_MAP_EXECUTE, &oa);
		}

		buf = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return STATUS_INTERNAL_ERROR;
}

NTSTATUS CreateSection(_Out_ PHANDLE SectionHandle, _In_ PWSTR lpLibFileName)
{
	int len = 0;
	PWSTR buf = 0;

	while (0 < (len = _snwprintf(buf, len, L"\\systemroot\\system32\\%s", lpLibFileName)))
	{
		if (buf)
		{
			UNICODE_STRING ObjectName;
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
			RtlInitUnicodeString(&ObjectName, buf);

			HANDLE hFile;
			IO_STATUS_BLOCK iosb;
			NTSTATUS status = NtOpenFile(&hFile, FILE_EXECUTE|SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

			if (0 <= status)
			{
				status = NtCreateSection(SectionHandle, SECTION_MAP_EXECUTE, 0, 0, PAGE_EXECUTE, SEC_IMAGE,hFile);
				NtClose(hFile);
			}

			return status;
		}

		buf = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return STATUS_INTERNAL_ERROR;
}

NTSTATUS CreateOrOpenSection(_Out_ PHANDLE SectionHandle, _In_ PWSTR lpLibFileName)
{
	NTSTATUS status = OpenSection(SectionHandle, lpLibFileName);
	return 0 > status ? CreateSection(SectionHandle, lpLibFileName) : STATUS_SUCCESS;
}

void DoRemoteMap(PBYTE pbBinary, PWSTR lpCommandLine)
{
	ULONG cch = (ULONG)wcslen(lpCommandLine);
	ULONG cbBinary = (1 + cch) * sizeof(WCHAR);

	if (CryptStringToBinaryW(lpCommandLine, cch, CRYPT_STRING_BASE64, pbBinary, &cbBinary, 0, 0))
	{
		if (sizeof(RSM) + sizeof(WCHAR) < cbBinary && !*(WCHAR*)(pbBinary + cbBinary - sizeof(WCHAR)))
		{
			RSM* p = (RSM*)pbBinary;

			HANDLE hSection, hProcess, hThread;
			if (0 <= CreateOrOpenSection(&hSection, p->LibFileName))
			{
				OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };
				CLIENT_ID cid = { (HANDLE)(ULONG_PTR)p->dwProcessId, (HANDLE)(ULONG_PTR)p->dwThreadId };

				NTSTATUS status;

				if (0 <= (status = NtOpenProcess(&hProcess, PROCESS_VM_OPERATION|PROCESS_VM_WRITE, &zoa, &cid)))
				{
					SIZE_T ViewSize = 0;
					PVOID BaseAddress = 0;

					//////////////////////////////////////////////////////////////////////////
					//
					// ERROR: Unable to find system process ****
					// ERROR: The process being debugged has either exited or cannot be accessed
					// ERROR: Many commands will not work properly
					// ERROR: Module load event for unknown process
					//
					//////////////////////////////////////////////////////////////////////////

					if (0 <= (status = ZwMapViewOfSection(hSection, hProcess, &BaseAddress, 
						0, 0, 0, &ViewSize, ViewShare, 0, PAGE_EXECUTE)))
					{
						if (0 <= (status = NtWriteVirtualMemory(hProcess, p->pBaseAddress, &BaseAddress, sizeof(BaseAddress), 0)))
						{
							if (0 <= (status = NtOpenThread(&hThread, THREAD_ALERT, &zoa, &cid)))
							{
								status = NtAlertThread(hThread);
								NtClose(hThread);
							}
						}

						if (0 > status)
						{
							ZwUnmapViewOfSection(hProcess, BaseAddress);
						}
					}

					NtClose(hProcess);
				}

				NtClose(hSection);
			}
		}
	}
}

PVOID MapDll(PCWSTR lpLibFileName)
{
	RSM* p = 0;
	int len = 0;
	PWSTR buf = 0;

	PVOID BaseAddress = 0;

	while (0 < (len = _snwprintf(buf, len, L"%s", lpLibFileName)))
	{
		ULONG cbBinary = sizeof(RSM) + ++len * sizeof(WCHAR);

		if (p)
		{
			p->pBaseAddress = &BaseAddress;
			p->dwThreadId = GetCurrentThreadId();
			p->dwProcessId = GetCurrentProcessId();

			PWSTR lpCommandLine = 0, psz = 0;
			ULONG cch = 0;
			buf = 0;

			while (CryptBinaryToStringW((PBYTE)p, cbBinary, 
				CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, psz, &cch))
			{
				if (lpCommandLine)
				{
					if (PWSTR lpApplicationName = new WCHAR[MINSHORT])
					{
						GetModuleFileNameW(0, lpApplicationName, MINSHORT * sizeof(WCHAR));

						if (GetLastError() == NOERROR)
						{
							STARTUPINFO si = { sizeof(si) };
							PROCESS_INFORMATION pi;

							*lpCommandLine = '\n';

							if (CreateProcessW(lpApplicationName, lpCommandLine, 0, 0, 0, 0, 0, 0, &si, &pi))
							{
								NtClose(pi.hThread);
								NtClose(pi.hProcess);

								LARGE_INTEGER DelayInterval = { 0, (LONG)MINLONG };
								if (STATUS_ALERTED != NtDelayExecution(TRUE, &DelayInterval))
								{
									BaseAddress = 0;
								}
							}
						}

						delete [] lpApplicationName;
					}

					break;
				}

				lpCommandLine = (PWSTR)alloca((1 + cch) * sizeof(WCHAR));
				psz = lpCommandLine + 1;
			}

			break;
		}

		p = (RSM*)alloca(cbBinary);
		buf = p->LibFileName;
	}

	return BaseAddress;
}

void NTAPI ep(PWSTR lpCommandLine)
{
	if ('\n' == *(lpCommandLine = GetCommandLineW()))
	{
		DoRemoteMap((PBYTE)lpCommandLine, lpCommandLine + 1);
		ExitProcess(0);
	}

	if (PVOID BaseAddress = MapDll(L"ntdll.dll"))
	{
		AreMappedFilesTheSame((PBYTE)BaseAddress, (PBYTE)GetModuleHandleW(L"ntdll"));
		ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
	}

	DetachDebugger();

	ExitProcess(ShowErrorBox(0, S_OK, L"ExitProcess", MB_ICONINFORMATION));
}