#include "stdafx.h"
#include "Common.h"

//////////////////////////////////////////////////////////////////////////
// ��ȡ�û�����
//
//////////////////////////////////////////////////////////////////////////
std::queue<std::string>* getUserInput()
{
    std::string strInput;
    std::string::size_type n;
    std::queue<std::string>* qu = new std::queue<std::string>;

    std::cout << "-";
    std::getline(std::cin, strInput, '\n');

    n = strInput.find(" ");
    while (std::string::npos != n)
    {
        qu->push(strInput.substr(0, n));
        strInput.erase(0, n + 1);
        n = strInput.find(" ");
    }

    qu->push(strInput);

    return qu;
}

//////////////////////////////////////////////////////////////////////////
// �����û������ָ��
// ����ֵ������ѭ������ FALSE������ѭ������ TRUE
//////////////////////////////////////////////////////////////////////////
BOOL analyzeInstruction(LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    BOOL bRet = TRUE;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDe->dwProcessId);
    HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, pDe->dwThreadId);

    // ����ָ��
    if (!qu->front().compare("g"))
    {
        doG(hProcess, pDe, qu);
        bRet = FALSE;
    }
    // bp + addr ָ��
    else if (!qu->front().compare("bp"))
    {
        doBP(hProcess, pDe, qu);
        bRet = TRUE;
    }
    // bpl
    else if (!qu->front().compare("bpl"))
    {
        doBPL(hProcess, pDe, qu);
        bRet = TRUE;
    }
    else if (!qu->front().compare("bpc"))
    {
        doBPC(hProcess, pDe, qu);
        bRet = TRUE;
    }
    else if (!qu->front().compare("bh"))
    {
        doBH(hThread, pDe, qu);
        bRet = TRUE;
    }
    else if (!qu->front().compare("bhl"))
    {
        doBHL(hProcess, pDe, qu);
        bRet = TRUE;
    }
    else if (!qu->front().compare("bhc"))
    {
        doBHC(hThread, pDe, qu);
        bRet = TRUE;
    }
    else if (!qu->front().compare("t"))
    {
        doT(hThread, pDe);
        bRet = FALSE;
    }
    else if (!qu->front().compare("u"))
    {
        doU(hProcess, hThread, pDe, qu);
        bRet = TRUE;
    }
    else if (!qu->front().compare("p"))
    {
        doP(hProcess, hThread, pDe);
        bRet = FALSE;
    }
    else if (!qu->front().compare("trace"))
    {
        doTRACE(hProcess, hThread, pDe, qu);
        bRet = FALSE;
    }

    delete qu;
    return bRet;
}

void doG(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    qu->pop();

    //����� g ��ֱ������
    if (qu->empty())
    {
    }
    // ��� g + ��ַ�����ڵ�ַ���¶ϵ㣬��ִ�е��ϵ㴦
    else
    {
        DWORD addr = 0;
        sscanf(qu->front().c_str(), "%x", &addr);
        // �������ϵ����������
        if (FALSE == g_pData->isSoftBPExist(addr))
        {
            setSoftBP(hProcess, TEMP_BREAKPOINT, addr);
        }
    }

    return;
}

void doBP(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    qu->pop();
    if (qu->empty())
    {
        // �������û�е�ַ��û����
    }
    else
    {
        DWORD addr = 0;
        sscanf(qu->front().c_str(), "%x", &addr);

        // �������ϵ����������
        if (FALSE == g_pData->isSoftBPExist(addr))
        {
            setSoftBP(hProcess, NORMAL_BREAKPOINT, addr);
        }
    }

    return;
}

void doBPL(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    LPSOFT_BP bp = g_pData->getFirstSoftBP();

    while (NULL != bp)
    {
        printf("%d 0x%08x\r\n", bp->m_nSequenceNumber, bp->m_bpAddr);
        bp = g_pData->getNextSoftBP();
    } 

    return;
}

void doBPC(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    qu->pop();
    if (qu->empty())
    {
        // �������û�е�ַ��û����
    }
    else
    {
        int iSequenceNumber = 0;
        sscanf(qu->front().c_str(), "%d", &iSequenceNumber);

        // �����ϵ�
        LPSOFT_BP bp = g_pData->getFirstSoftBP();
        while (NULL != bp)
        {
            if (iSequenceNumber == bp->m_nSequenceNumber)
            {
                // �ָ��ϵ㴦ָ�����������ɾ���ϵ�
                restoreInstruction(hProcess, bp->m_bpAddr, &bp->m_oldCode);
                g_pData->deleteBP(bp->m_bpAddr);
                break;
            }
            bp = g_pData->getNextSoftBP();
        }

        if (NULL == bp)
        {
            printf("BreakPoint doesn't exist.");
        }

    }

}

//////////////////////////////////////////////////////////////////////////
//bh    ��ַ  �ϵ㳤��(1, 2, 4)	e(ִ��)/w(д��)/a(����)
//
//////////////////////////////////////////////////////////////////////////
void doBH(HANDLE hThread, LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    DWORD dwAddr = NULL;
    eType dwBPType;
    DWORD dwLen = 0;
    if (BH_COMMAND_LENGTH != qu->size())
    {
        printf("Syntax error.\n");
        return;
    }

    // Ӳ���ϵ��ַ
    qu->pop();
    sscanf(qu->front().c_str(), "%x", &dwAddr);
    if (NULL == dwAddr)
    {
        printf("Syntax error.\n");
        return;
    }

    // Ӳ���ϵ㳤��
    qu->pop();
    sscanf(qu->front().c_str(), "%x", &dwLen);
    if (0 == dwLen)
    {
        printf("Syntax error.\n");
        return;
    }

    // Ӳ���ϵ�����
    qu->pop();
    if (!qu->front().compare("e"))
    {
        dwBPType = EXECUTE_HARDWARE;
        dwLen = 1;
    }
    else if (!qu->front().compare("w"))
    {
        dwBPType = WRITE_HARDWARE;
    }
    else if (!qu->front().compare("a"))
    {
        dwBPType = ACCESS_HARDWARE;
    }
    else
    {
        printf("Syntax error.\n");
        return;
    }

    if (g_pData->isHardBPExist(dwAddr, dwLen, dwBPType))
    {
        return;
    }

    DWORD iSNumber = setHardBP(hThread, dwAddr, dwLen, dwBPType);
    if (-1 == iSNumber)
    {
        printf("Set hardware breakpoint fail.\r\n");
        return;
    }

    LPHARD_BP hardBP = new HARD_BP;
    hardBP->m_nSequenceNumber = iSNumber;
    hardBP->m_bpAddr = dwAddr;
    hardBP->m_type = dwBPType;
    hardBP->m_bCurrentBP = FALSE;
    hardBP->m_dwLen = dwLen;
    g_pData->addBP(hardBP);

    return;
}

void doBHL(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    LPHARD_BP bp = g_pData->getFirstHardBP();

    while (NULL != bp)
    {
        char cType = { 0 };
        switch (bp->m_type)
        {
        case 0:
        {
            cType = 'e';
        }
        break;
        case 1:
        {
            cType = 'w';
        }
        break;
        case 3:
        {
            cType = 'a';
        }
        break;
        default:
            break;
        }

        printf("%d 0x%08x %d %c\r\n", bp->m_nSequenceNumber, bp->m_bpAddr, bp->m_dwLen, cType);
        bp = g_pData->getNextHardBP();
    }

    return;
}

void doBHC(HANDLE hThread, LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    qu->pop();
    if (qu->empty())
    {
        // �������û�е�ַ��û����
    }
    else
    {
        int iSequenceNumber = 0;
        sscanf(qu->front().c_str(), "%d", &iSequenceNumber);

        if (FALSE == g_pData->isHardBPExist(iSequenceNumber))
        {
            printf("Breakpoint doesn't exist.\r\n");
            return;
        }

        abortHardBP(hThread, iSequenceNumber);
        g_pData->deleteHardBP(iSequenceNumber);

    }
    
    return;
}

// �õ�������
void doT(HANDLE hThread, LPDEBUG_EVENT pDe)
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &ctx);

    ctx.EFlags |= 0x100;
    SetThreadContext(hThread, &ctx);

    g_pData->setStepIn();
    return;
}

void doU(HANDLE hProcess, HANDLE hThread, LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    DWORD dwAddr = 0;

    qu->pop();
    if (qu->empty())
    {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &ctx);
        dwAddr = ctx.Eip;
    }
    else
    {
        sscanf(qu->front().c_str(), "%x", &dwAddr);
        if (NULL == dwAddr)
        {
            printf("Syntax error.\n");
            return;
        }
        // ���� u �ĵ�ַ
        g_pData->setNewU();
    }

    // ׼������
    std::vector<LPDISASSEMBLY_INSTRUCT> vectorAsm;
    unsigned char szCodeBuff[0x800] = { 0 };
    DWORD dwNumberOfBytesRead = 0;
    DWORD dwNumberOfInsDisasm = 8;

    if (!g_pData->isNewU())
    {
        dwAddr = g_pData->getUAddr();
    }

    ReadProcessMemory(hProcess, (LPVOID)dwAddr, szCodeBuff, sizeof(szCodeBuff), &dwNumberOfBytesRead);
    disassembly(
        (unsigned int*)&dwNumberOfInsDisasm, 
        &vectorAsm, 
        szCodeBuff, 
        dwNumberOfBytesRead, 
        (unsigned int*)&dwAddr);

    std::vector<LPDISASSEMBLY_INSTRUCT>::iterator it = vectorAsm.begin();
    for (; it != vectorAsm.end(); it++)
    {
        printf("%08X %-30s%-30s\r\n", (*it)->nCodeAddress, (*it)->szOpcodeBuf, (*it)->szAsmBuf);
        delete (*it);
    }

    g_pData->setUAddr(dwAddr);
    return;
}

void doP(HANDLE hProcess, HANDLE hThread, LPDEBUG_EVENT pDe)
{
    // �ж���һ��ָ���Ƿ�������ϵ㡣����У�ֱ�����У����û�У�����һ�е�ָ����һ������ϵ㣬Ȼ�����н���
    // ����������� BreakPointException��ֱ�ӻָ�ԭ����ָ��
    // �����Ӳ���ϵ㣬��Ӱ��ԭ�������̡�
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

    // û�� call ��ʱ����Ͳ���һ�� 
    if (strstr((char*)vectorAsm[0]->szAsmBuf, "call"))
    {
        if (FALSE == g_pData->isSoftBPExist(dwAddr))
        {
            setSoftBP(hProcess, TEMP_BREAKPOINT, dwAddr);
        }
    }
    else
    {
        doT(hThread, pDe);
    }

    return;
}

void doTRACE(HANDLE hProcess, HANDLE hThread, LPDEBUG_EVENT pDe, std::queue<std::string>* qu)
{
    DWORD dwAddr = 0;

    qu->pop();
    if (qu->empty())
    {
        printf("Syntax error.\n");
        return;
    }

    sscanf(qu->front().c_str(), "%x", &dwAddr);
    if (NULL == dwAddr)
    {
        printf("Syntax error.\n");
        return;
    }
    
    printf("Please input file name: ");
    std::string strName;
    std::cin >> strName;
    
    if (!g_pData->openFile(strName.c_str()))
    {
        printf("File path error.\n");
        return;
    }
    
    g_pData->setTrace();
    g_pData->traceStepIn(dwAddr, hThread);

    return;
}