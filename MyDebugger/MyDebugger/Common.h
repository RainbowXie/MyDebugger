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
};



// ��������
extern CDebugData* g_pData;

DWORD OnCreateProcessDebugEvent(LPDEBUG_EVENT pDe);
DWORD OnExceptionDebugEvent(LPDEBUG_EVENT pDe);
DWORD OnBreakPoint(LPDEBUG_EVENT pDe);
DWORD OnSingleStep(LPDEBUG_EVENT pDe);

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