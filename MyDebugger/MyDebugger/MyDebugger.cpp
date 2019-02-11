// MyDebugger.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "Common.h"

CDebugData *g_pData;

int main(int argc, char** argv)
{
    g_pData = new CDebugData;

    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };
    BOOL bRet = CreateProcess(
        argv[1],
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi);

    if (0 == bRet)
    {
        showDebugerError(_T("Open Process Fail. "));
    }
    
    DEBUG_EVENT de;
    while (WaitForDebugEvent(&de, INFINITE))
    {
        g_pData->setNewU();

        DWORD dwCoutinueStatus = DBG_EXCEPTION_NOT_HANDLED;

        switch (de.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
        {
            dwCoutinueStatus = OnExceptionDebugEvent(&de);
        }
        break;
        case CREATE_THREAD_DEBUG_EVENT:
        {

        }
        break;
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            dwCoutinueStatus = OnCreateProcessDebugEvent(&de);

        }
        break;
        case EXIT_THREAD_DEBUG_EVENT:
        {

        }
        break;
        case EXIT_PROCESS_DEBUG_EVENT:
        {

        }
        break;
        case LOAD_DLL_DEBUG_EVENT:
        {

        }
        break;
        case UNLOAD_DLL_DEBUG_EVENT:
        {

        }
        break;
        case OUTPUT_DEBUG_STRING_EVENT:
        {

        }
        break;
        case RIP_EVENT:
        {

        }
        break;
        default:
        {
            showDebugerError(_T("Debug Error: unknown code. "));
        }
        break;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwCoutinueStatus);
    }


    return 0;
}

