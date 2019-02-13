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
// 单步异常
// 一般软件断点、硬件断点会到这来。
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

    // 判断是否由硬件断点引发的 singlestep
    PDR6 pDr6 = (PDR6)&ctx.Dr6;
    int ValidSeat = ctx.Dr6 & 0xf;
    if (0 != ValidSeat)
    {
        // 把掩码位转换成序号
        int iSNumber = 0;
        while (ValidSeat = ValidSeat >> 1)
        {
            iSNumber++;
        }
        // 判断该 Dr 位的断点类型
        int BPType = (eType)((ctx.Dr7 & (3 << (16 + iSNumber * 4))) >> (16 + iSNumber * 4));

        // 如果是执行断点，设单步
        if (EXECUTE_HARDWARE == BPType)
        {
            abortHardBP(hThread, iSNumber); //取消硬件执行断点

            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;
            GetThreadContext(hThread, &ctx);
            ctx.EFlags |= 0x100;       // 设置单步
            ctx.Dr6 = 0;
            SetThreadContext(hThread, &ctx);

            // 设置要还原的硬件断点
            g_pData->setCurrentHardwareBP(*(&ctx.Dr0 + iSNumber));

            // 当单步步入进入硬件断点时，仍然停留在当前指令，
            // 没有走到下一条指令，单步步过没有完成。
            // 直接再走一步，下一条指令中进入单步步过。
            if (g_pData->isStepIn())
            {
                g_pData->setStepIn();
                return DBG_CONTINUE;
            }
        }
        else
        {

        }

        // 断点到达，获取用户输入
        BOOL bRet = TRUE;
        while (bRet)
        {
            bRet = analyzeInstruction(pDe, getUserInput());
        }

        dwRet = DBG_CONTINUE;
        return dwRet;
    }


    // 走到这说明是单步中断引发的，而不是硬件断点引发的
    //     if (pDr6->BS)
    //     {
    // 找到刚刚走过的断点，并重设断点
    LPSOFT_BP currentSoftBP = g_pData->getCurrentSoftBP();
    LPHARD_BP currentHardBP = g_pData->getCurrentHardwareBP();

    // 如果 currentBP 不为 NULL，则说明是软件执行断点。
    if (NULL != currentSoftBP)
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDe->dwProcessId);
        if (NULL == hProcess)
        {
            showDebugerError(_T("重设断点失败。"));
            return dwRet;
        }

        // 将断点重设回去
        if (!setBreakPoint(hProcess, currentSoftBP->m_bpAddr, &currentSoftBP->m_oldCode))
        {
            return dwRet;
        }
    }

    if (NULL != currentHardBP)
    {
        // 恢复硬件执行断点
        DWORD dwAddr = currentHardBP->m_bpAddr;
        if (NULL != dwAddr)
        {
            setHardBP(hThread, dwAddr, EXECUTE_HARDWARE_LEN, EXECUTE_HARDWARE);
        }
    }

    // 判断是否是单步步入
    if (TRUE == g_pData->isStepIn())
    {
        // 等待用户输入
        BOOL bRet = TRUE;
        while (bRet)
        {
            bRet = analyzeInstruction(pDe, getUserInput());
        }
    }

    // 是否 trace
    GetThreadContext(hThread, &ctx);
    if (g_pData->isTrace())
    {
        // 准备环境
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

        // 检测是否 trace 完
        if (g_pData->isTraceOver(ctx.Eip))
        {
            g_pData->closeFile();
            // 等待用户输入
            BOOL bRet = TRUE;
            while (bRet)
            {
                bRet = analyzeInstruction(pDe, getUserInput());
            }
        }
        else
        {
            // 如果 trace 没完，则设置单步
            ctx.EFlags |= 0x100;       // 设置单步
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
        CONTEXT ctx = { 0 };
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
// 访问异常
// 无论是不是内存断点，执行完后都要设单步恢复原来的内存属性
// 流程：恢复发生异常的内存地址的分页属性，保存发生异常的内存地址，设单步，在单步中重设异常的内存地址的分页属性为
// PAGE_NOACCESS
//////////////////////////////////////////////////////////////////////////
DWORD OnExceptionAccessViolation(LPDEBUG_EVENT pDe)
{
    DWORD dwRet = DBG_CONTINUE;
    LPEXCEPTION_DEBUG_INFO pExceptionDebugInfo = &pDe->u.Exception;
    PEXCEPTION_RECORD pExceptionRecord = &pExceptionDebugInfo->ExceptionRecord;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDe->dwProcessId);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pDe->dwThreadId);

    //判断异常读写的内存地址是否位于断点范围内
    PMEMORY_BP pBP = g_pData->getMemoryBP(pExceptionRecord->ExceptionInformation[1], pExceptionRecord->ExceptionInformation[0]);
    if (pBP)
    {
        // 内存断点触发
        pBP->m_bCurrentBP = TRUE;
        // 恢复内存断点
        abortMemoryBreakPoint(hProcess, hThread, pBP->m_bpAddr, pBP->m_dwOldProtect);
        // 等待用户输入
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