#include "stdafx.h"
#include "Common.h"


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
// һ������ϵ㡢Ӳ���ϵ�ᵽ������
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
    PDR6 pDr6 = (PDR6)&ctx.Dr6;
    int ValidSeat = ctx.Dr6 & 0xf;
    if (0 != ValidSeat)
    {
        // ������λת�������
        int iSNumber = 0;
        while (ValidSeat = ValidSeat >> 1)
        {
            iSNumber++;
        }
        // �жϸ� Dr λ�Ķϵ�����
        int BPType = (eType)((ctx.Dr7 & (3 << (16 + iSNumber * 4))) >> (16 + iSNumber * 4));

        // �����ִ�жϵ㣬�赥��
        if (EXECUTE_HARDWARE == BPType)
        {
            abortHardBP(hThread, iSNumber); //ȡ��Ӳ��ִ�жϵ�

            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;
            GetThreadContext(hThread, &ctx);
            ctx.EFlags |= 0x100;       // ���õ���
            ctx.Dr6 = 0;
            SetThreadContext(hThread, &ctx);

            // ����Ҫ��ԭ��Ӳ���ϵ�
            g_pData->setCurrentHardwareBP(*(&ctx.Dr0 + iSNumber));

            // ����������/�������Ӳ���ϵ�ʱ����Ȼͣ���ڵ�ǰָ�
            // û���ߵ���һ��ָ���������û����ɡ�
            // ֱ������һ������һ��ָ���н��뵥��������
            if (g_pData->isStepIn() || g_pData->isStepOver())
            {
                g_pData->setStepIn();
                return DBG_CONTINUE;
            }
            if (g_pData->isStepOver())
            {
                g_pData->setStepOver();
                return DBG_CONTINUE;
            }
        }
        else
        {

        }

        // �ϵ㵽���ȡ�û�����
        BOOL bRet = TRUE;
        while (bRet)
        {
            bRet = analyzeInstruction(pDe, getUserInput());
        }

        dwRet = DBG_CONTINUE;
        return dwRet;
    }


    // �ߵ���˵���ǵ����ж������ģ�������Ӳ���ϵ�������
//     if (pDr6->BS)
//     {
        // �ҵ��ո��߹��Ķϵ㣬������ϵ�
    LPSOFT_BP currentSoftBP = g_pData->getCurrentSoftBP();
    LPHARD_BP currentHardBP = g_pData->getCurrentHardwareBP();

    // ��� currentBP ��Ϊ NULL����˵�������ִ�жϵ㡣
    if (NULL != currentSoftBP)
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDe->dwProcessId);
        if (NULL == hProcess)
        {
            showDebugerError(_T("����ϵ�ʧ�ܡ�"));
            return dwRet;
        }

        // ���ϵ������ȥ
        if (!setBreakPoint(hProcess, currentSoftBP->m_bpAddr, &currentSoftBP->m_oldCode))
        {
            return dwRet;
        }
    }

    if (NULL != currentHardBP)
    {
        // �ָ�Ӳ��ִ�жϵ�
        DWORD dwAddr = currentHardBP->m_bpAddr;
        if (NULL != dwAddr)
        {
            setHardBP(hThread, dwAddr, EXECUTE_HARDWARE_LEN, EXECUTE_HARDWARE);
        }
    }

    // �ж��Ƿ��ǵ�������
    if (TRUE == g_pData->isStepIn())
    {
        // �ȴ��û�����
        BOOL bRet = TRUE;
        while (bRet)
        {
            bRet = analyzeInstruction(pDe, getUserInput());
        }
    }
    else if (TRUE == g_pData->isStepOver())
    {
    }
/*    }*/


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
// ����ֵ��û�п�λ���� -1
//////////////////////////////////////////////////////////////////////////
DWORD setHardBP(HANDLE hThread, DWORD dwAddr, DWORD dwLen, eType BPType)
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
        return iSNumber;
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

    return iSNumber;
}

//////////////////////////////////////////////////////////////////////////
//�������ܣ���ȡ���е�Ӳ���ϵ� DR
//����ֵ�����ؿ��� DR ����ţ�û�п��е��򷵻� -1
//////////////////////////////////////////////////////////////////////////
DWORD getVacancySeat(LPCONTEXT pCtx)
{
    int i = 0;
    int iFlag = pCtx->Dr7 & 0xff;
    while (i < HARDWARE_SEAT_COUNT)
    {
        if (!(iFlag & (1 << (2 * i))) && !g_pData->isHardBPExist(i))
        {
            return i;
        } 
        i++;
    }

//     LPDWORD pDr = &pCtx->Dr0;
//     for (int i = 0; i < HARDWARE_SEAT_COUNT; i++, pDr++)
//     {
//         if (NULL == *pDr)
//         {
//             return i;
//         }
//     }

    return -1;
}

//////////////////////////////////////////////////////////////////////////
// ȡ��Ӳ���ϵ�
//
//////////////////////////////////////////////////////////////////////////
BOOL abortHardBP(HANDLE hThread, DWORD dwSNumber)
{
    BOOL bRet = FALSE;

    //��ȡ�Ĵ�������
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &ctx);

    // ����λ����Ϊ 0
    ctx.Dr7 &= ~(-1 & (1 << (dwSNumber * 2)));
    ctx.Dr7 &= ~(-1 & (0xf << (dwSNumber * 4 + 16))); // ���� RW��LEN λ
    //*(&ctx.Dr0 + dwSNumber) = NULL;    // �����λ���ˣ������� DR6 ��Ϊ0��
    ctx.Dr6 = 0;
    SetThreadContext(hThread, &ctx);

    bRet = TRUE;
    return bRet;
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