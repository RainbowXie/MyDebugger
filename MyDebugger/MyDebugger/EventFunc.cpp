#include "stdafx.h"
#include "Common.h"

#define HARDWARE_SEAT_COUNT 4
//////////////////////////////////////////////////////////////////////////
// ���öϵ�
// ����ֵ���ɹ����� TRUE��ʧ�ܷ��� FALSE
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
// �ָ��� CC �ƻ���ָ��
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
// �����쳣
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

    // �ж��Ƿ���Ӳ���ϵ������� singlestep 
    int ValidSeat = ctx.Dr6 & 0xf;
    if (0 == ValidSeat)
    {
    }

    // �ҵ��ո��߹��Ķϵ㣬������ϵ�
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
            showDebugerError(_T("����ϵ�ʧ�ܡ�"));
            return dwRet;
        }

        // ���ϵ������ȥ
        if (!setBreakPoint(hProcess, currentBP->m_bpAddr, &currentBP->m_oldCode))
        {
            return dwRet;
        }
    }
    
    dwRet = DBG_CONTINUE;
    return dwRet;
}

//////////////////////////////////////////////////////////////////////////
// �ϵ��쳣
//
//////////////////////////////////////////////////////////////////////////
DWORD OnBreakPoint(LPDEBUG_EVENT pDe)
{
    DWORD dwRet = DBG_CONTINUE;

    // ϵͳ�ϵ��򲻹ܣ�����ִ��
    if (g_pData->IsSystemBP())
    {
        return dwRet;
    }

    LPEXCEPTION_DEBUG_INFO pExceptionDebugInfo = &pDe->u.Exception;
    PEXCEPTION_RECORD pExceptionRecord = &pExceptionDebugInfo->ExceptionRecord;

    // �ָ��ϵ㸲�ǵ�ָ��
    if (g_pData->isSoftBPExist((DWORD)pExceptionRecord->ExceptionAddress))
    {
        // ��ȡ���̺��߳̾��
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDe->dwProcessId);
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pDe->dwThreadId);

        // ��ȡ��ǰ�ϵ�
        LPSOFT_BP pSoftBP = g_pData->getSoftBP((DWORD)pExceptionRecord->ExceptionAddress);

        // �ָ�ԭ����ָ��
        restoreInstruction(hProcess, (DWORD)pExceptionRecord->ExceptionAddress, &pSoftBP->m_oldCode);
        
        // ��ȡ�Ĵ�������
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &ctx);

        // �ϵ㴦��ִ�й��ˣ�������Ҫ�� EIP ���ϵ�ǰ
        ctx.Eip--;

        // �����һ��ϵ㣬������������Ա�ִ��������ָ����ٰѶϵ����ȥ
        if (NORMAL_BREAKPOINT == pSoftBP->m_type)
        {
            // ��Ϊ��ǰ�ϵ�
            pSoftBP->m_bCurrentBP = TRUE;
            ctx.EFlags |= 0x100;
        }
        // �������ʱ�ϵ����赥������ִ��
        else if (TEMP_BREAKPOINT == pSoftBP->m_type)
        {
            // ��������ɾ����ʱ BP
            g_pData->deleteBP(pSoftBP->m_bpAddr);
        }

        SetThreadContext(hThread, &ctx);

        CloseHandle(hProcess);
        CloseHandle(hThread);
    }

    // �ϵ㴦�ȴ��û�����
    BOOL bRet = TRUE;
    while (bRet)
    {
        bRet = analyzeInstruction(pDe, getUserInput());
    }
    

    return dwRet;
}



//////////////////////////////////////////////////////////////////////////
// ����Ӳ���ϵ�
// ����ֵ��û�п�λ���� FALSE
//////////////////////////////////////////////////////////////////////////
BOOL setHardBP(HANDLE hThread, DWORD dwAddr, DWORD dwLen, eType BPType)
{
    dwLen--;

    BOOL bRet = FALSE;

    // ��ȡ�Ĵ�������
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &ctx);
    DWORD iSNumber = -1;

    // ȡ��λ���öϵ�
    iSNumber = getVacancySeat(&ctx);
    if (-1 == iSNumber)
    {
        return FALSE;
    }

    LPDWORD pDr = &ctx.Dr0;
    PDR7 pDr7 = (PDR7)&ctx.Dr7;
    pDr += iSNumber;
    *pDr = dwAddr;
    ctx.Dr7 |= (1 << (iSNumber * 2));   // ���� L λ
    ctx.Dr7 |= (BPType << (iSNumber * 4 + 16)); // ���� RW λ
    ctx.Dr7 |= (dwLen << (iSNumber * 4 + 18));      // ���� LEN λ
    ctx.Dr6 = 0;

    SetThreadContext(hThread, &ctx);

    return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//�������ܣ���ȡ���е�Ӳ���ϵ� DR
//����ֵ�����ؿ��� DR ����ţ�û�п��е��򷵻� -1
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
    OutputDebugString(_T("\r\n ����ԭ��"));
    OutputDebugString((LPCWSTR)lpMsgBuf);
    // Free the buffer.
    LocalFree(lpMsgBuf);
}