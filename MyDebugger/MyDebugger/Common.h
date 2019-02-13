#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <map>
#include <queue>
#include <vector>
#include <Shlwapi.h>
#include <fstream>
#include "..\Disasm\Decode2Asm.h"

#pragma comment(lib, "Shlwapi.lib")

// ���߳�д����ӣ�����������������


// ����ϵ�ִ�����̣�
// 1. ��������ϵ�Ϊ 00400000
// 2. ���������ϵ㣬ExceptionAddress Ϊ 0040000��dwDebugEventCode = EXCEPTION_DEBUG_EVENT��
// pExceptionRecord->ExceptionCode Ϊ EXCEPTION_BREAKPOINT��EIP Ϊ 00400001��˵���Ѿ�ִ�й� 00400000 �ˣ�
// 3.1 �������ֵΪ DBG_EXCEPTION_NOT_HANDLED�����쳣����ϵͳ����
//      3.1.1 ���ϵͳ�����ˣ�����̼�������ִ�У�
//      3.1.2 ���ϵͳû��������쳣�ڶ����������Գ���dwDebugEventCode Ϊ EXCEPTION_DEBUG_EVENT��pExceptionRecord->ExceptionCode Ϊ EXCEPTION_BREAKPOINT��EIP Ϊ 00400001
//          3.1.2.1 ������Գ�����δ��������������Խ���
//          3.1.2.2 ������Գ������ˣ�����̼�������ִ�У�
// 3.2 �������ֵΪ DBG_CONTINUE������̼�������ִ��

// Ӳ��ִ�жϵ�ִ������
// 1. ����Ӳ��ִ�жϵ�Ϊ 00400000
// 2. ���������ϵ㣬ExceptionCode Ϊ EXCEPTION_SINGLE_STEP��EIP Ϊ 00400000��ExceptionAddress Ϊ 00400000����δִ�иöϵ㣩
// 3. �������öϵ�ȥ�������һֱ������ϵ㡣
// ע��������� Dr6����ÿ�� SetThreadContext ǰ�� Dr6 ��Ϊ 0��

 //Ӳ�����ʡ�д��ϵ����ڷ��ʡ�д��ָ�����һ��ָ��
//���������� EXCEPTION_SINGLE_STEP �쳣��Ȼ�����ִ�н��̣���������������Ҫ�ϲ�����������ʡ�д��ϵ�

// ��������/���� ���� CC �ϵ㣺
// �龰��eip = 00400000��������ԭ��Ϊ 3 ���ֽڣ�����һ�� CC �ϵ㣬��ʱ�õ�������
// ִ�����̣�
// 1. ִ�� CC��eip = 00400001������ BP �쳣��
// 2. �� BP �쳣�л�ԭ CC��eip ��ԭΪ 00400000���õ���
// 3. ���뵥���쳣��eip = 00400003������һ������Ķϵ��Ȼָ���Ȼ��ȴ��û�����
#define EXECUTE_HARDWARE_LEN 1
#define HARDWARE_SEAT_COUNT 4
#define  BH_COMMAND_LENGTH 4
//////////////////////////////////////////////////////////////////////////
//
//
//////////////////////////////////////////////////////////////////////////
enum eType
{
    EXECUTE_HARDWARE = 0, //ִ��Ӳ���ϵ�
    WRITE_HARDWARE = 1,		//д��Ӳ���ϵ�
    ACCESS_HARDWARE = 3,	//����Ӳ���ϵ�

    SYS_BREAKPOINT, //ϵͳ�ϵ�
    NORMAL_BREAKPOINT, //��ͨ�ϵ�
    TEMP_BREAKPOINT, //��ʱ�ϵ�

};

//////////////////////////////////////////////////////////////////////////
//����ϵ�
//
//////////////////////////////////////////////////////////////////////////
typedef struct tagBreakPoint
{
    int m_nSequenceNumber;     // ���
    eType m_type;                   // �ϵ�����
    DWORD m_bpAddr;     // �ϵ��ַ
    char m_oldCode;              // �ϵ�ԭ����ָ��
    int m_bActive;         // �Ƿ����öϵ�
    BOOL m_bCurrentBP; // �Ƿ��ǵ�ǰ�Ķϵ㣬��������ϵ�
}SOFT_BP, *LPSOFT_BP;

typedef struct tagHardBreakPoint
{
    int m_nSequenceNumber;     // ���
    eType m_type;                   // �ϵ�����
    DWORD m_bpAddr;     // �ϵ��ַ
    DWORD m_dwLen;      // �ϵ㳤��
    BOOL m_bCurrentBP; // �Ƿ��ǵ�ǰ�Ķϵ㣬��������ϵ�
}HARD_BP, *LPHARD_BP;

typedef struct tagMemoryBreakPoint
{
    int m_nSequenceNumber;     // ���
    int m_type;                   // �ϵ�����
    DWORD m_bpAddr;     // �ϵ��ַ
    BOOL m_bCurrentBP; // �Ƿ��ǵ�ǰ�Ķϵ㣬��������ϵ�
    DWORD m_dwOldProtect;  //ԭ�����ڴ�����
}MEMORY_BP, *PMEMORY_BP;
typedef struct tagMemBPShow
{
    int m_nSequenceNumber;
    int m_nLen;
    DWORD m_bpAddr;
    int m_type;
}MEM_BP_SHOW, *PMEM_BP_SHOW;

typedef struct tagDisassembly
{
    unsigned int nCodeAddress;                   // ָ���ַ
    unsigned char szOpcodeBuf[0x40];    // Ӳ����
    unsigned char szAsmBuf[0x40];    // ָ��
}DISASSEMBLY, *LPDISASSEMBLY_INSTRUCT;

//////////////////////////////////////////////////////////////////////////
// DR7 �ı�־
//
//////////////////////////////////////////////////////////////////////////
typedef struct  tagDR7
{
    int L0 : 1;
    int G0 : 1;
    int L1 : 1;
    int G1 : 1;
    int L2 : 1;
    int G2 : 1;
    int L3 : 1;
    int G3 : 1;
    int unuserd : 8;
    int RW0 : 2;
    int LEN0 : 2;
    int RW1 : 2;
    int LEN1 : 2;
    int RW2 : 2;
    int LEN2 : 2;
    int RW3 : 2;
    int LEN3 : 2;
}DR7, *PDR7;

typedef struct tagDR6
{
    int B0 : 1;
    int B1 : 1;
    int B2 : 1;
    int B3 : 1;
    int unused0 : 10;
    int BS : 1;
    int unused1 : 17;
}DR6, *PDR6;


DWORD OnCreateProcessDebugEvent(LPDEBUG_EVENT pDe);
DWORD OnExceptionDebugEvent(LPDEBUG_EVENT pDe);
DWORD OnBreakPoint(LPDEBUG_EVENT pDe);
DWORD OnSingleStep(LPDEBUG_EVENT pDe);
DWORD OnExceptionAccessViolation(LPDEBUG_EVENT pDe);

BOOL restoreInstruction(HANDLE hProcess, DWORD dwAddrDest, char* pBuffOfOldCode);

void showDebugerError(TCHAR* err);
BOOL setBreakPoint(HANDLE hProcess, DWORD dwAddrDest, char* pBuffOfOldCode);
BOOL setSoftBP(HANDLE hProcess, eType BPType, DWORD addr);

DWORD getVacancySeat(LPCONTEXT pCtx);
DWORD setHardBP(HANDLE hThread, DWORD dwAddr, DWORD dwLen, eType BPType);
BOOL abortHardBP(HANDLE hThread, DWORD dwSNumber);
BOOL disassembly(
    unsigned int* nInstructionCount,
    std::vector<LPDISASSEMBLY_INSTRUCT> *pVectorAsm,
    unsigned char *pCode,
    unsigned int nCodeLength,
    unsigned int *nCodeAddress);

BOOL SetMemoryBreakPoint(HANDLE hProcess, DWORD dwAddrDst, DWORD dwLen, LPDWORD pdwOldProtect);
BOOL abortMemoryBreakPoint(HANDLE hProcess, HANDLE hThread, DWORD dwAddrDst, DWORD dwOldProtect);
BOOL readMemory(HANDLE hProcess, DWORD dwCount, char* szBuff, DWORD dwAddrDest);


BOOL analyzeInstruction(LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
std::queue<std::string>* getUserInput();

void doG(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBP(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBPL(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBPC(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBH(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBHL(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBHC(HANDLE hThread, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doT(HANDLE hThread, LPDEBUG_EVENT pDe);
void doP(HANDLE hProcess, HANDLE hThread, LPDEBUG_EVENT pDe);
void doU(HANDLE hProcess, HANDLE hThread, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doTRACE(HANDLE hProcess, HANDLE hThread, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBM(HANDLE hThread, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBMC(HANDLE hProcess, HANDLE hThread, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBML();
void doR(HANDLE hThread);
void doDD(HANDLE hProcess, HANDLE hThread, std::queue<std::string>* qu);
void doQ(HANDLE hProcess, HANDLE hThread);
void doLS();
void doES();
//////////////////////////////////////////////////////////////////////////
//���������õõ�������
//
//////////////////////////////////////////////////////////////////////////
class CDebugData
{
public:
    CDebugData()
    {
        m_softIt = m_SoftBPMap.end();
        m_HardIt = m_HardBPVector.end();
    }
    ~CDebugData()
    {

    }
    BOOL IsSystemBP()
    {
        if (TRUE == m_bIsSystemBP)
        {
            m_bIsSystemBP = FALSE;
            return TRUE;
        }
        return m_bIsSystemBP;
    }

    void addBP(LPSOFT_BP softBP)
    {
        m_iCount++;
        softBP->m_nSequenceNumber = m_iCount;
        softBP->m_bCurrentBP = FALSE;
        m_SoftBPMap.insert(m_SoftBPMap.end(), std::make_pair(softBP->m_bpAddr, softBP));
        return;
    }

    // ���Ӳ���ϵ�
    void addBP(LPHARD_BP hardBP)
    {
        m_HardBPVector.push_back(hardBP);
        //m_HardBPVector.insert(m_HardBPVector.end(), std::make_pair(hardBP->m_bpAddr, hardBP));
        return;
    }

    // �ϵ���ڷ��� TRUE�������ڷ��� FALSE
    BOOL isHardBPExist(DWORD addr, DWORD dwLen, eType BPType)
    {
        std::vector<LPHARD_BP>::iterator Iter;
        for (Iter = m_HardBPVector.begin(); Iter != m_HardBPVector.end(); Iter++)
        {
            if (((*Iter)->m_bpAddr <= addr && addr < (*Iter)->m_bpAddr + (*Iter)->m_dwLen)
                &&(*Iter)->m_type == BPType)
            {
                return TRUE;
            }
        }

        return FALSE;
    }
    // �ϵ���ڷ��� TRUE�������ڷ��� FALSE
    BOOL isHardBPExist(DWORD dwSNumber)
    {
        std::vector<LPHARD_BP>::iterator Iter;
        for (Iter = m_HardBPVector.begin(); Iter != m_HardBPVector.end(); Iter++)
        {
            if ((*Iter)->m_nSequenceNumber == dwSNumber)
            {
                return TRUE;
            }
        }

        return FALSE;
    }

    // �ϵ���ڷ��� TRUE�������ڷ��� FALSE
    BOOL isSoftBPExist(DWORD addr)
    {
        auto m_softIt = m_SoftBPMap.find(addr);

        if (m_softIt == m_SoftBPMap.end())
        {
            return FALSE;
        }

        return TRUE;
    }

    LPSOFT_BP getSoftBP(DWORD addr)
    {
        std::map<DWORD, LPSOFT_BP>::iterator m_softIt;
        m_softIt = m_SoftBPMap.find(addr);
        return m_softIt->second;
    }

    LPHARD_BP getHardBP(DWORD SNumber)
    {
        std::vector<LPHARD_BP>::iterator Iter;
        for (Iter = m_HardBPVector.begin(); Iter != m_HardBPVector.end(); Iter++)
        {
            if ((*Iter)->m_nSequenceNumber == SNumber)
            {

                return *Iter;
            }
        }

        return NULL;
    }

    LPSOFT_BP getFirstSoftBP()
    {
        m_softIt = m_SoftBPMap.begin();
        if (m_softIt != m_SoftBPMap.end())
        {
            return m_softIt->second;
        }

        return NULL;
    }
    LPSOFT_BP getNextSoftBP()
    {
        m_softIt++;
        if (m_SoftBPMap.end() == m_softIt)
        {
            return NULL;
        }
        return m_softIt->second;
    }

    LPHARD_BP getFirstHardBP()
    {
        m_HardIt = m_HardBPVector.begin();
        if (m_HardIt != m_HardBPVector.end())
        {
            return (*m_HardIt);
        }
        return NULL;
    }
    LPHARD_BP getNextHardBP()
    {
        m_HardIt++;
        if (m_HardBPVector.end() == m_HardIt)
        {
            return NULL;
        }
        return *m_HardIt;
    }

    // ��������ɾ����������ȡ���ϵ�
    void deleteBP(DWORD addr)
    {
        auto m_softIt = m_SoftBPMap.find(addr);

        delete m_softIt->second;
        m_SoftBPMap.erase(m_softIt);

        return;
    }

    // ��������ɾ���ϵ�
    // TRUE ɾ���ɹ���FALSE ɾ��ʧ��
    BOOL deleteHardBP(DWORD SNumber)
    {
        std::vector<LPHARD_BP>::iterator Iter;
        for (Iter = m_HardBPVector.begin(); Iter != m_HardBPVector.end(); Iter++)
        {
            if ((*Iter)->m_nSequenceNumber == SNumber)
            {
                delete (*Iter);
                m_HardBPVector.erase(Iter);
                return TRUE;
            }
        }


        return FALSE;
    }

    LPSOFT_BP getCurrentSoftBP()
    {
        auto m_softIt = m_SoftBPMap.begin();
        for (; m_softIt != m_SoftBPMap.end();m_softIt++)
        {
            if (TRUE == m_softIt->second->m_bCurrentBP)
            {
                m_softIt->second->m_bCurrentBP = FALSE;
                return m_softIt->second;
            }     
        }
        return NULL;
    }

    // Ӳ���ϵ�
    void setCurrentHardwareBP(DWORD currentHardwareBP)
    {
        std::vector<LPHARD_BP>::iterator Iter;
        for (Iter = m_HardBPVector.begin(); Iter != m_HardBPVector.end(); Iter++)
        {
            if ((*Iter)->m_bpAddr == currentHardwareBP)
            {
                (*Iter)->m_bCurrentBP = TRUE;
                return;
            }
        }
    }

    LPHARD_BP getCurrentHardwareBP()
    {
        std::vector<LPHARD_BP>::iterator Iter;
        for (Iter = m_HardBPVector.begin(); Iter != m_HardBPVector.end(); Iter++)
        {
            if ((*Iter)->m_bCurrentBP == TRUE)
            {
                (*Iter)->m_bCurrentBP = FALSE;
                return (*Iter);
            }
        }
        return NULL;
    }

    BOOL isStepIn()
    {
        if (TRUE == m_bStepIn)
        {
            m_bStepIn = FALSE;
            return TRUE;
        }
        return FALSE;
    }

    void setStepIn()
    {
        m_bStepIn = TRUE;
    }

    // �����ж��Ƿ�Ҫ���� u �ĵ�ַ
    void setNewU()
    {
        m_bNewUAddr = TRUE;
        return;
    }

    BOOL isNewU()
    {
        if (m_bNewUAddr == TRUE)
        {
            m_bNewUAddr = FALSE;
            return TRUE;
        }
        return FALSE;
    }
    void setUAddr(DWORD dwUAddr)
    {
        m_uAddr = dwUAddr;
    }

    DWORD getUAddr()
    {
        return m_uAddr;
    }

    // �����ж��Ƿ�Ҫ���� u �ĵ�ַ
    void setNewDD()
    {
        m_bNewDDAddr = TRUE;
        return;
    }

    BOOL isNewDD()
    {
        if (m_bNewDDAddr == TRUE)
        {
            m_bNewDDAddr = FALSE;
            return TRUE;
        }
        return FALSE;
    }
    void setDDAddr(DWORD dwDDAddr)
    {
        m_DDAddr = dwDDAddr;
    }

    DWORD getDDAddr()
    {
        return m_DDAddr;
    }

    bool openFile(const char* szName)
    {
        m_TraceFile = new std::fstream;
        m_TraceFile->open(szName, std::ios::in | std::ios::out | std::ios::trunc);

        if (m_TraceFile->is_open())
        {
            return true;
        }
        return false;
    }
    void closeFile()
    {
        m_TraceFile->close();
        delete m_TraceFile;
    }
    void writeFile(LPDISASSEMBLY_INSTRUCT pAsm)
    {
        char* szAddr = new char[sizeof(pAsm->nCodeAddress) * 2 + sizeof(pAsm->szAsmBuf) + sizeof(pAsm->szOpcodeBuf)];

        std::sprintf(szAddr, "%08x %-30s%-30s\r\n", pAsm->nCodeAddress, pAsm->szOpcodeBuf, pAsm->szAsmBuf);

        *m_TraceFile << szAddr;
        m_TraceFile->flush();
        delete[] szAddr;
    }

    void traceStepIn(DWORD dwAddr, HANDLE hThread)
    {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &ctx);

        ctx.EFlags |= 0x100;
        SetThreadContext(hThread, &ctx);

        m_dwTraceAddr = dwAddr;
    }

    BOOL isTrace()
    {
        return m_bTrace;
    }

    BOOL isTraceOver(DWORD dwAddr)
    {
        if (dwAddr == m_dwTraceAddr)
        {
            m_dwTraceAddr = 0;
            m_bTrace = FALSE;
            return TRUE;
        }
        return FALSE;
    }

    void setTrace()
    {
        
        m_bTrace = TRUE;
    }

    //////////////////////////////////////////////////////////////////////////
    // �ڴ�ϵ�

    // �ϵ���ڷ��� TRUE�������ڷ��� FALSE
    BOOL isMemoryBPExist(DWORD addr, DWORD dwLen, int BPType)
    {
        std::vector<PMEMORY_BP>::iterator Iter;
        for (Iter = m_MemoryBPVector.begin(); Iter != m_MemoryBPVector.end(); Iter++)
        {
            if ((*Iter)->m_bpAddr >= addr 
                && (*Iter)->m_bpAddr < addr + dwLen
                && (*Iter)->m_type == BPType)
            {
                return TRUE;
            }
//             // ���������Ҫ����
//             // ��һ�֣�
//             //   |_______|
//             //      |________|
//             if ((*Iter)->m_bpAddr <= addr 
//                 && addr <= ((*Iter)->m_bpAddr + (*Iter)->m_dwLen) 
//                 && ((*Iter)->m_bpAddr + (*Iter)->m_dwLen) < addr + dwLen)
//             {
// 
//             }
//             // �ڶ��֣�
//             //   |_______|
//             //|______|
//             else if (addr < (*Iter)->m_bpAddr 
//                 && (addr + dwLen) <= (*Iter)->m_bpAddr + (*Iter)->m_dwLen)
//             {
//             }
//             // �����֣�
//             //   |_______|
//             //|____________|
//             else if (addr <= (*Iter)->m_bpAddr)
//             {
//             }
        }

        return FALSE;
    }

    void SetMemoryBP(DWORD dwAddr, DWORD dwLen, DWORD type, DWORD dwOldProtect)
    {
        PMEMORY_BP pBP = NULL;

        for (unsigned int i = 0; i < dwLen; i++)
        {
            pBP = new MEMORY_BP;


            pBP->m_bCurrentBP = FALSE;
            pBP->m_bpAddr = dwAddr;
            pBP->m_dwOldProtect = dwOldProtect;
            pBP->m_type = type;
            pBP->m_nSequenceNumber = m_iMemBPCount;

            m_MemoryBPVector.push_back(pBP);

            dwAddr++;
        }
        m_iMemBPCount++;
    }

    PMEMORY_BP getMemoryBP(DWORD dwAddr, DWORD type)
    {
        std::vector<PMEMORY_BP>::iterator Iter;
        int nType = 0;

        if (0 == type && 8 == type)
        {
            nType = PAGE_NOACCESS;
        }
        else if(1 == type)
        {
            nType = PAGE_READONLY;
        }
        else
        {
            return NULL;
        }

        for (Iter = m_MemoryBPVector.begin(); Iter != m_MemoryBPVector.end(); Iter++)
        {
            if (dwAddr == (*Iter)->m_bpAddr)
            {
                //����ϵ�Ϊ���ʶϵ㣬��ֱ�ӷ��ضϵ㣻
                //����ϵ�Ϊд��ϵ㣬���ж��쳣�Ƿ�Ϊ PAGE_READONLY
                if (PAGE_NOACCESS == (*Iter)->m_type)
                {
                    return (*Iter);
                }
                else if(PAGE_READONLY == (*Iter)->m_type && PAGE_READONLY == nType)
                {
                    return (*Iter);
                }
            }
        }

        return NULL;
    }

    BOOL isMemAttributeChange()
    {
        if (TRUE == m_bIsMemAttributeChange)
        {
            m_bIsMemAttributeChange = FALSE;
            return TRUE;
        }
        return FALSE;
    }

    PMEMORY_BP getCurrentBP()
    {
        std::vector<PMEMORY_BP>::iterator Iter;
        for (Iter = m_MemoryBPVector.begin(); Iter != m_MemoryBPVector.end(); Iter++)
        {
            if (TRUE == (*Iter)->m_bCurrentBP)
            {
                (*Iter)->m_bCurrentBP = FALSE;
                return (*Iter);
            }
        }

        return NULL;
    }

    DWORD getMemoryPage(DWORD dwAddr)
    {
        unsigned int iInteger = dwAddr / 0x1000 * 0x1000;
        
        std::vector<PMEMORY_BP>::iterator Iter;
        for (Iter = m_MemoryBPVector.begin(); Iter != m_MemoryBPVector.end(); Iter++)
        {
            if (iInteger <= (*Iter)->m_bpAddr && iInteger + 0x1000 > (*Iter)->m_bpAddr)
            {
                
                return (*Iter)->m_dwOldProtect;
            }
        }

        return PAGE_EXECUTE_READWRITE;
    }

    void setMemoryAttributeChange(DWORD dwAddr)
    {
        m_bIsMemAttributeChange = TRUE;
        m_dwChangedAddr = dwAddr;
    }
    // ��ȡ�������ڴ����Եĵ�ַ
    DWORD getChangedAddr()
    {
        return m_dwChangedAddr;
    }
    void cleanChangedAddr()
    {
        m_dwChangedAddr = NULL;
    }

    // ���б���ɾ�����ڴ�ϵ㣬�������б�����Ƿ���ͬһ��ҳ�������ڴ�ϵ㣬
    // ����оͱ�����ҳ�ڴ����ԣ����û�оͻָ���ҳ�ڴ�����
    void deleteMemoryAddr(HANDLE hProcess, HANDLE hThread, DWORD dwSNumber)
    {
        std::vector<PMEMORY_BP>::iterator Iter;
        std::vector<PMEMORY_BP>::iterator ItFirst;
        std::vector<PMEMORY_BP>::iterator ItLast;
        bool bhasOtherBP = false;
        bool bIsFirst = true;

        for (Iter = m_MemoryBPVector.begin(); Iter != m_MemoryBPVector.end(); Iter++)
        {
            if (dwSNumber == (*Iter)->m_nSequenceNumber)
            {
                if (bIsFirst)
                {
                    ItFirst = Iter;
                    bIsFirst = false;
                }
                ItLast = Iter;
                // ����Ƿ���ͬһ��ҳ�������ڴ�ϵ�
                DWORD dwPageAttribute = (*Iter)->m_bpAddr / 0x1000 * 0x1000;

                std::vector<PMEMORY_BP>::iterator It;
                for (It = m_MemoryBPVector.begin(); It != m_MemoryBPVector.end(); It++)
                {
                    if ((*It)->m_bpAddr >= dwPageAttribute && (*It)->m_bpAddr < dwPageAttribute + 0x1000
                        && (*It)->m_nSequenceNumber != dwSNumber)
                    {
                        bhasOtherBP = true;
                        break;
                    }
                }

                // ���û�оͻָ���ҳ�ڴ�����
                if (!bhasOtherBP)
                {
                    abortMemoryBreakPoint(hProcess, hThread, (*Iter)->m_bpAddr, (*Iter)->m_dwOldProtect);
                }
                delete *Iter;
            }
        }
        //
        //ItFirst;
        ItLast++;
        m_MemoryBPVector.erase(ItFirst, ItLast);
        return;
    }

    MEM_BP_SHOW getFirstMemoryBP()
    {
        MEM_BP_SHOW BpShow = { 0 };


        m_MemoryIter = m_MemoryBPVector.begin();
        if (m_MemoryIter == m_MemoryBPVector.end())
        {
            return BpShow;
        }


        DWORD dwSNumber = 0;
        DWORD dwLen = 0;

        BpShow.m_bpAddr = (*m_MemoryIter)->m_bpAddr;
        BpShow.m_type = (*m_MemoryIter)->m_type;

        for (dwSNumber = (*m_MemoryIter)->m_nSequenceNumber; 
            m_MemoryIter != m_MemoryBPVector.end() && dwSNumber == (*m_MemoryIter)->m_nSequenceNumber;
            m_MemoryIter++, dwLen++)
        {

            BpShow.m_nSequenceNumber = dwSNumber;
        }


        BpShow.m_nLen = dwLen;

        return BpShow;
    }
    MEM_BP_SHOW getNextMemoryBP()
    {
        MEM_BP_SHOW BpShow = { 0 };
        if (m_MemoryIter == m_MemoryBPVector.end())
        {
            return BpShow;
        }
        DWORD dwSNumber = 0;
        DWORD dwLen = 0;

        BpShow.m_bpAddr = (*m_MemoryIter)->m_bpAddr;
        BpShow.m_type = (*m_MemoryIter)->m_type;

        for (dwSNumber = (*m_MemoryIter)->m_nSequenceNumber;
            m_MemoryIter != m_MemoryBPVector.end() && dwSNumber == (*m_MemoryIter)->m_nSequenceNumber;
            m_MemoryIter++, dwLen++)
        {
            BpShow.m_nSequenceNumber = dwSNumber;
        }
        BpShow.m_nLen = dwLen;

        return BpShow;
    }

    BOOL hasLoadScriptVector()
    {
        if (m_LoadScriptVector.empty())
        {
            return FALSE;
        }
        return TRUE;
    }

    void addScript(std::string* strBuf)
    {

        m_ExportScriptVector.insert(m_ExportScriptVector.end(), *strBuf);
    }
    void exportScript(std::fstream *pScriptFile)
    {
        std::vector<std::string>::iterator It;
        for (It = m_ExportScriptVector.begin(); It != m_ExportScriptVector.end() - 1; It++)
        {
            *pScriptFile << *It;
            *pScriptFile << "\n";
            pScriptFile->flush();
        }
        m_ExportScriptVector.clear();
    }

    void importScript(std::fstream *pScriptFile)
    {
        std::string str;
        while (!pScriptFile->eof())
        {
            getline(*pScriptFile, str, '\n');
            m_LoadScriptVector.insert(m_LoadScriptVector.end(), str);
        }
    }
    std::string getLoadScript()
    {
        std::string str = m_LoadScriptVector.front();
        m_LoadScriptVector.erase(m_LoadScriptVector.begin());
        return str;
    }
private:

    BOOL m_bNewUAddr = TRUE;
    DWORD m_uAddr = NULL;   // u �����õĵ�ַ
    // ����ϵ�
    int m_iCount = 0;
    std::map<DWORD, LPSOFT_BP> m_SoftBPMap;     // ��ַ������ϵ�����
    std::map<DWORD, LPSOFT_BP>::iterator m_softIt;              
    BOOL m_bIsSystemBP = TRUE;

    //
    std::vector<LPHARD_BP> m_HardBPVector;     // ��ַ������ϵ�����
    std::vector<LPHARD_BP>::iterator m_HardIt;

    //�������롢��������
    BOOL m_bStepIn = FALSE;

    // ���ٲ���ĵ�ַ
    DWORD m_dwTraceAddr = 0;
    std::fstream *m_TraceFile = NULL;
    BOOL m_bTrace = FALSE;

    // �ڴ�ϵ�
    int m_iMemBPCount = 0;
    std::vector<PMEMORY_BP> m_MemoryBPVector;     // �ڴ�ϵ�����
    std::vector<PMEM_BP_SHOW> m_MemBPShowVector;    // ������ʾ�Ķϵ�
    std::vector<PMEMORY_BP>::iterator m_MemoryIter;
    BOOL m_bIsMemAttributeChange = FALSE;
    DWORD m_dwChangedAddr = 0;         // �����������ڴ��ַ

    // DD
    BOOL m_bNewDDAddr = TRUE;
    DWORD m_DDAddr = NULL;   // u �����õĵ�ַ

    // ES
    std::vector<std::string> m_ExportScriptVector;

    // LS
    std::vector<std::string> m_LoadScriptVector;
};



// ��������
extern CDebugData* g_pData;
