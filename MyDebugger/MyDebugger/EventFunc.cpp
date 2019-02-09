#include "stdafx.h"
#include "Common.h"

#define HARDWARE_SEAT_COUNT 4
//////////////////////////////////////////////////////////////////////////
// 设置断点
// 返回值：成功返回 TRUE，失败返回 FALSE
//////////////////////////////////////////////////////////////////////////
BOOL setBreakPoint(HANDLE hProcess, DWORD dwAddrDest, char* pBuffOfOldCode)
{
    BOOL bRet = TRUE;
    DWORD dwOldProtect = 0;
    DWORD dwNumberOfBytesRead = 0;
    DWORD dwNumberOfBytesWritten = 0;
    unsigned char cCode = 0xCC;



    if (!VirtualProtectEx(hProcess, (LPVOID)dwAddrDest, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        showDebugerError(_T("setBreakPoint fail."));
        return FALSE;
    }

    if (!ReadProcessMemory(hProcess, (LPVOID)dwAddrDest, pBuffOfOldCode, sizeof(cCode), &dwNumberOfBytesRead))
    {
        showDebugerError(_T("setBreakPoint fail."));
        return FALSE;
    }
    if (!WriteProcessMemory(hProcess, (LPVOID)dwAddrDest, &cCode, sizeof(cCode), &dwNumberOfBytesWritten))
    {
        showDebugerError(_T("setBreakPoint fail."));
        return FALSE;
    }
    if (!VirtualProtectEx(hProcess, (LPVOID)dwAddrDest, 1, dwOldProtect, &dwOldProtect))
    {
        showDebugerError(_T("setBreakPoint fail."));
        return FALSE;
    }

    return bRet;
}

BOOL setSoftBP(HANDLE hProcess, eType BPType, DWORD addr)
{
    BOOL bRet = TRUE;

    LPSOFT_BP pSoftBP = new SOFT_BP;
    pSoftBP->m_bActive = FALSE;
    pSoftBP->m_bpAddr = addr;
    pSoftBP->m_type = BPType;
    pSoftBP->m_oldCode = 0;
    pSoftBP->m_bCurrentBP = FALSE;

    if (!setBreakPoint(
        hProcess,
        addr,
        &pSoftBP->m_oldCode))
    {
        bRet = FALSE;
    }

    g_pData->addBP(pSoftBP);
    return bRet;
}

//////////////////////////////////////////////////////////////////////////
// 恢复被 CC 破坏的指令
//
//////////////////////////////////////////////////////////////////////////
BOOL restoreInstruction(HANDLE hProcess, DWORD dwAddrDest, char* pBuffOfOldCode)
{
    BOOL bRet = TRUE;
    DWORD dwOldProtect = 0;
    DWORD dwNumberOfBytesWritten = 0;

    if (!VirtualProtectEx(hProcess, (LPVOID)dwAddrDest, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, (LPVOID)dwAddrDest, pBuffOfOldCode, sizeof(*pBuffOfOldCode), &dwNumberOfBytesWritten))
    {
        return FALSE;
    }
    if (!VirtualProtectEx(hProcess, (LPVOID)dwAddrDest, 1, dwOldProtect, &dwOldProtect))
    {
        return FALSE;
    }

    return bRet;
}


//////////////////////////////////////////////////////////////////////////
// 单步异常
//
//////////////////////////////////////////////////////////////////////////
DWORD OnSingleStep(LPDEBUG_EVENT pDe)
{
    DWORD  dwRet = DBG_EXCEPTION_NOT_HANDLED;
    LPEXCEPTION_DEBUG_INFO pExceptionDebugInfo = &pDe->u.Exception;
    PEXCEPTION_RECORD pExceptionRecord = &pExceptionDebugInfo->ExceptionRecord;

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pDe->dwThreadId);
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &ctx);

    // 判断是否由硬件断点引发的 singlestep 
    int ValidSeat = ctx.Dr6 & 0xf;
    if (0 == ValidSeat)
    {
    }

    // 找到刚刚走过的断点，并重设断点
    LPSOFT_BP currentBP = g_pData->getCurrentSoftBP();
    if (!currentBP)
    {
        dwRet = DBG_CONTINUE;
        return dwRet;
    }

    if (NORMAL_BREAKPOINT == currentBP->m_type)
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDe->dwProcessId);
        if (NULL == hProcess)
        {
            showDebugerError(_T("重设断点失败。"));
            return dwRet;
        }

        // 将断点重设回去
        if (!setBreakPoint(hProcess, currentBP->m_bpAddr, &currentBP->m_oldCode))
        {
            return dwRet;
        }
    }
    
    dwRet = DBG_CONTINUE;
    return dwRet;
}

//////////////////////////////////////////////////////////////////////////
// 断点异常
//
//////////////////////////////////////////////////////////////////////////
DWORD OnBreakPoint(LPDEBUG_EVENT pDe)
{
    DWORD dwRet = DBG_CONTINUE;

    // 系统断点则不管，继续执行
    if (g_pData->IsSystemBP())
    {
        return dwRet;
    }

    LPEXCEPTION_DEBUG_INFO pExceptionDebugInfo = &pDe->u.Exception;
    PEXCEPTION_RECORD pExceptionRecord = &pExceptionDebugInfo->ExceptionRecord;

    // 恢复断点覆盖的指令
    if (g_pData->isSoftBPExist((DWORD)pExceptionRecord->ExceptionAddress))
    {
        // 获取进程和线程句柄
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDe->dwProcessId);
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pDe->dwThreadId);

        // 获取当前断点
        LPSOFT_BP pSoftBP = g_pData->getSoftBP((DWORD)pExceptionRecord->ExceptionAddress);

        // 恢复原来的指令
        restoreInstruction(hProcess, (DWORD)pExceptionRecord->ExceptionAddress, &pSoftBP->m_oldCode);
        
        // 获取寄存器环境
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &ctx);

        // 断点处已执行过了，所以需要置 EIP 到断点前
        ctx.Eip--;

        // 如果是一般断点，则设个单步，以便执行完这条指令后再把断点设回去
        if (NORMAL_BREAKPOINT == pSoftBP->m_type)
        {
            // 设为当前断点
            pSoftBP->m_bCurrentBP = TRUE;
            ctx.EFlags |= 0x100;
        }
        // 如果是零时断点则不设单步继续执行
        else if (TEMP_BREAKPOINT == pSoftBP->m_type)
        {
            // 从链表中删除临时 BP
            g_pData->deleteBP(pSoftBP->m_bpAddr);
        }

        SetThreadContext(hThread, &ctx);

        CloseHandle(hProcess);
        CloseHandle(hThread);
    }

    // 断点处等待用户命令
    BOOL bRet = TRUE;
    while (bRet)
    {
        bRet = analyzeInstruction(pDe, getUserInput());
    }
    

    return dwRet;
}



//////////////////////////////////////////////////////////////////////////
// 设置硬件断点
// 返回值：没有空位返回 FALSE
//////////////////////////////////////////////////////////////////////////
BOOL setHardBP(HANDLE hThread, DWORD dwAddr, DWORD dwLen, eType BPType)
{
    dwLen--;

    BOOL bRet = FALSE;

    // 获取寄存器环境
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &ctx);
    DWORD iSNumber = -1;

    // 取空位设置断点
    iSNumber = getVacancySeat(&ctx);
    if (-1 == iSNumber)
    {
        return FALSE;
    }

    LPDWORD pDr = &ctx.Dr0;
    PDR7 pDr7 = (PDR7)&ctx.Dr7;
    pDr += iSNumber;
    *pDr = dwAddr;
    ctx.Dr7 |= (1 << (iSNumber * 2));   // 设置 L 位
    ctx.Dr7 |= (BPType << (iSNumber * 4 + 16)); // 设置 RW 位
    ctx.Dr7 |= (dwLen << (iSNumber * 4 + 18));      // 设置 LEN 位
    ctx.Dr6 = 0;

    SetThreadContext(hThread, &ctx);

    return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//函数功能：获取空闲的硬件断点 DR
//返回值：返回空闲 DR 的序号，没有空闲的则返回 -1
//////////////////////////////////////////////////////////////////////////
DWORD getVacancySeat(LPCONTEXT pCtx)
{
    LPDWORD pDr = &pCtx->Dr0;
    for (int i = 0; i < HARDWARE_SEAT_COUNT; i++, pDr++)
    {
        if (NULL == *pDr)
        {
            return i;
        }
    }

    return -1;
}

//////////////////////////////////////////////////////////////////////////
//
//
//////////////////////////////////////////////////////////////////////////
void showDebugerError(TCHAR* err)
{
    LPVOID lpMsgBuf;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        0, // Default language
        (LPTSTR)&lpMsgBuf,
        0,
        NULL
    );
    // Process any inserts in lpMsgBuf.
    // ...
    // Display the string.
    OutputDebugString(err);
    OutputDebugString(_T("\r\n 错误原因："));
    OutputDebugString((LPCWSTR)lpMsgBuf);
    // Free the buffer.
    LocalFree(lpMsgBuf);
}