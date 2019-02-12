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
//nInstructionCount ��Ҫ��������ָ�� 
//pCode ��Ҫ����ָ�����
// nCodeLength ����ָ������Ĵ�С
// pVectorAsm ����������ָ��
// nCodeAddress ����ָ��ĵ�ַ���������������һ��ָ��ĵ�ַ
//////////////////////////////////////////////////////////////////////////
BOOL disassembly(
    unsigned int* nInstructionCount, 
    std::vector<LPDISASSEMBLY_INSTRUCT> *pVectorAsm,
    unsigned char *pCode, 
    unsigned int nCodeLength,
    unsigned int *nCodeAddress)
{
    BOOL bRet = TRUE;
    unsigned int nCount = 0;
    unsigned int nCodeSize = 0;
    unsigned int nDisassembledCount = 0;
    char szAsmBuf[0x40] = { 0 };
    char szOpcodeBuf[0x40];    // Ӳ����
    
    while (nCount < nCodeLength && nDisassembledCount < *nInstructionCount)
    {
        LPDISASSEMBLY_INSTRUCT pAsm = new DISASSEMBLY;

        Decode2AsmOpcode(
            pCode, 
            szAsmBuf,
            szOpcodeBuf,
            &nCodeSize, (unsigned int)*nCodeAddress);

        memcpy(pAsm->szOpcodeBuf, szOpcodeBuf, sizeof(szOpcodeBuf));
        memcpy(pAsm->szAsmBuf, szAsmBuf, sizeof(szAsmBuf));
        pAsm->nCodeAddress = *nCodeAddress;
        pVectorAsm->push_back(pAsm);

        pCode += nCodeSize;
        nCount += nCodeSize;
        *nCodeAddress += nCodeSize;
        nDisassembledCount++;
    }

    // û�н������㹻��ָ��
    if (nDisassembledCount < *nInstructionCount - 1)
    {
        bRet = FALSE;
    }

    *nInstructionCount = nDisassembledCount;
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
    OutputDebugStringA(("\r\n ����ԭ��"));
    OutputDebugStringW((LPCWSTR)lpMsgBuf);
    // Free the buffer.
    LocalFree(lpMsgBuf);
}
