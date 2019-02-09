#include "stdafx.h"
#include "Common.h"


//////////////////////////////////////////////////////////////////////////
//
//
//////////////////////////////////////////////////////////////////////////
DWORD OnCreateProcessDebugEvent(LPDEBUG_EVENT pDe)
{
    DWORD dwRet = DBG_CONTINUE;
    LPCREATE_PROCESS_DEBUG_INFO pCreateProcessDebugInfo = &pDe->u.CreateProcessInfo;

    // 设置程序入口点断点
    setSoftBP(
        pCreateProcessDebugInfo->hProcess, 
        NORMAL_BREAKPOINT, 
        (DWORD)pCreateProcessDebugInfo->lpStartAddress);

    return dwRet;
}

DWORD OnExceptionDebugEvent(LPDEBUG_EVENT pDe)
{
    DWORD dwRet = DBG_EXCEPTION_NOT_HANDLED;
    LPEXCEPTION_DEBUG_INFO pExceptionDebugInfo = &pDe->u.Exception;
    PEXCEPTION_RECORD pExceptionRecord = &pExceptionDebugInfo->ExceptionRecord;

    switch (pExceptionRecord->ExceptionCode)
    {
    case EXCEPTION_BREAKPOINT:
    {
        dwRet = OnBreakPoint(pDe);
    }
    break;
    case EXCEPTION_SINGLE_STEP:
    {
        dwRet = OnSingleStep(pDe);
    }
    break;
    default:
        break;
    }

    return dwRet;
}


