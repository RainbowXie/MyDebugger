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

    // ���ó�����ڵ�ϵ�
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
    case EXCEPTION_ACCESS_VIOLATION:
    {
        dwRet = OnExceptionAccessViolation(pDe);
    }
    break;
    default:
        break;
    }

    return dwRet;
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
    HANDLE hProcess = OpenProcess(THREAD_ALL_ACCESS, FALSE, pDe->dwProcessId);


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

            // �������������Ӳ���ϵ�ʱ����Ȼͣ���ڵ�ǰָ�
            // û���ߵ���һ��ָ���������û����ɡ�
            // ֱ������һ������һ��ָ���н��뵥��������
            if (g_pData->isStepIn())
            {
                g_pData->setStepIn();
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

    // �Ƿ� trace
    GetThreadContext(hThread, &ctx);
    if (g_pData->isTrace())
    {
        // ׼������
        std::vector<LPDISASSEMBLY_INSTRUCT> vectorAsm;
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &ctx);
        DWORD dwAddr = ctx.Eip;
        unsigned char szCodeBuff[0x80] = { 0 };
        DWORD dwNumberOfBytesRead = 0;
        DWORD dwNumberOfInsDisasm = 1;

        ReadProcessMemory(hProcess, (LPVOID)dwAddr, szCodeBuff, sizeof(szCodeBuff), &dwNumberOfBytesRead);
        disassembly(
            (unsigned int*)&dwNumberOfInsDisasm,
            &vectorAsm,
            szCodeBuff,
            dwNumberOfBytesRead,
            (unsigned int*)&dwAddr);

        g_pData->writeFile(vectorAsm[0]);
        delete vectorAsm[0];

        // ����Ƿ� trace ��
        if (g_pData->isTraceOver(ctx.Eip))
        {
            g_pData->closeFile();
            // �ȴ��û�����
            BOOL bRet = TRUE;
            while (bRet)
            {
                bRet = analyzeInstruction(pDe, getUserInput());
            }
        }
        else
        {
            // ��� trace û�꣬�����õ���
            ctx.EFlags |= 0x100;       // ���õ���
            ctx.Dr6 = 0;
            SetThreadContext(hThread, &ctx);
        }
    }

    if (g_pData->isMemAttributeChange())
    {
        //PMEMORY_BP pBP = g_pData->getCurrentBP();
        DWORD dwAddr = g_pData->getChangedAddr();
        DWORD dwOldProtect = 0;
        SetMemoryBreakPoint(hProcess, dwAddr, 1, &dwOldProtect);
        g_pData->cleanChangedAddr();
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
        CONTEXT ctx = { 0 };
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
// �����쳣
// �����ǲ����ڴ�ϵ㣬ִ�����Ҫ�赥���ָ�ԭ�����ڴ�����
// ���̣��ָ������쳣���ڴ��ַ�ķ�ҳ���ԣ����淢���쳣���ڴ��ַ���赥�����ڵ����������쳣���ڴ��ַ�ķ�ҳ����Ϊ
// PAGE_NOACCESS
//////////////////////////////////////////////////////////////////////////
DWORD OnExceptionAccessViolation(LPDEBUG_EVENT pDe)
{
    DWORD dwRet = DBG_CONTINUE;
    LPEXCEPTION_DEBUG_INFO pExceptionDebugInfo = &pDe->u.Exception;
    PEXCEPTION_RECORD pExceptionRecord = &pExceptionDebugInfo->ExceptionRecord;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDe->dwProcessId);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pDe->dwThreadId);

    //�ж��쳣��д���ڴ��ַ�Ƿ�λ�ڶϵ㷶Χ��
    PMEMORY_BP pBP = g_pData->getMemoryBP(pExceptionRecord->ExceptionInformation[1], pExceptionRecord->ExceptionInformation[0]);
    if (pBP)
    {
        // �ڴ�ϵ㴥��
        pBP->m_bCurrentBP = TRUE;
        // �ָ��ڴ�ϵ�
        abortMemoryBreakPoint(hProcess, hThread, pBP->m_bpAddr, pBP->m_dwOldProtect);
        // �ȴ��û�����
        BOOL bRet = TRUE;
        while (bRet)
        {
            bRet = analyzeInstruction(pDe, getUserInput());
        }
    }

    
    abortMemoryBreakPoint(
        hProcess, hThread, 
        pExceptionRecord->ExceptionInformation[1], 
        g_pData->getMemoryPage(pExceptionRecord->ExceptionInformation[1]));
    
    g_pData->setMemoryAttributeChange(pExceptionRecord->ExceptionInformation[1]);

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return dwRet;
}