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

// 单线程写是天坑！！！！！！！！！


// 软件断点执行流程：
// 1. 设置软件断点为 00400000
// 2. 进程遇到断点，ExceptionAddress 为 0040000，dwDebugEventCode = EXCEPTION_DEBUG_EVENT，
// pExceptionRecord->ExceptionCode 为 EXCEPTION_BREAKPOINT，EIP 为 00400001（说明已经执行过 00400000 了）
// 3.1 如果返回值为 DBG_EXCEPTION_NOT_HANDLED，则异常交给系统处理，
//      3.1.1 如果系统处理了，则进程继续往下执行；
//      3.1.2 如果系统没处理，则该异常第二次来到调试程序，dwDebugEventCode 为 EXCEPTION_DEBUG_EVENT，pExceptionRecord->ExceptionCode 为 EXCEPTION_BREAKPOINT，EIP 为 00400001
//          3.1.2.1 如果调试程序仍未处理，则结束被调试进程
//          3.1.2.2 如果调试程序处理了，则进程继续往下执行；
// 3.2 如果返回值为 DBG_CONTINUE，则进程继续往下执行

// 硬件执行断点执行流程
// 1. 设置硬件执行断点为 00400000
// 2. 进程遇到断点，ExceptionCode 为 EXCEPTION_SINGLE_STEP，EIP 为 00400000，ExceptionAddress 为 00400000（还未执行该断点）
// 3. 若不将该断点去掉，则会一直来这个断点。
// 注意如果不用 Dr6，在每次 SetThreadContext 前将 Dr6 置为 0。

 //硬件访问、写入断点会断在访问、写入指令的下一条指令
//触发后会进入 EXCEPTION_SINGLE_STEP 异常，然后继续执行进程，不会再来，不需要断步配合来过访问、写入断点

// 单步步入/步过 遇上 CC 断点：
// 情景：eip = 00400000，此命令原来为 3 个字节，设了一个 CC 断点，此时置单步步入
// 执行流程：
// 1. 执行 CC，eip = 00400001，进入 BP 异常。
// 2. 在 BP 异常中还原 CC，eip 还原为 00400000，置单步
// 3. 进入单步异常，eip = 00400003，将上一条命令的断点先恢复，然后等待用户输入
#define EXECUTE_HARDWARE_LEN 1
#define HARDWARE_SEAT_COUNT 4
#define  BH_COMMAND_LENGTH 4
//////////////////////////////////////////////////////////////////////////
//
//
//////////////////////////////////////////////////////////////////////////
enum eType
{
    EXECUTE_HARDWARE = 0, //执行硬件断点
    WRITE_HARDWARE = 1,		//写入硬件断点
    ACCESS_HARDWARE = 3,	//访问硬件断点

    SYS_BREAKPOINT, //系统断点
    NORMAL_BREAKPOINT, //普通断点
    TEMP_BREAKPOINT, //临时断点
};

//////////////////////////////////////////////////////////////////////////
//软件断点
//
//////////////////////////////////////////////////////////////////////////
typedef struct tagBreakPoint
{
    int m_nSequenceNumber;     // 序号
    eType m_type;                   // 断点类型
    DWORD m_bpAddr;     // 断点地址
    char m_oldCode;              // 断点原来的指令
    int m_bActive;         // 是否启用断点
    BOOL m_bCurrentBP; // 是否是当前的断点，用于重设断点
}SOFT_BP, *LPSOFT_BP;

typedef struct tagHardBreakPoint
{
    int m_nSequenceNumber;     // 序号
    eType m_type;                   // 断点类型
    DWORD m_bpAddr;     // 断点地址
    DWORD m_dwLen;      // 断点长度
    BOOL m_bCurrentBP; // 是否是当前的断点，用于重设断点
}HARD_BP, *LPHARD_BP;

typedef struct tagDisassembly
{
    unsigned int nCodeAddress;                   // 指令地址
    unsigned char szOpcodeBuf[0x40];    // 硬编码
    unsigned char szAsmBuf[0x40];    // 指令
}DISASSEMBLY, *LPDISASSEMBLY_INSTRUCT;

//////////////////////////////////////////////////////////////////////////
// DR7 的标志
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
//保存所有用得到的数据
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

    // 添加硬件断点
    void addBP(LPHARD_BP hardBP)
    {
        m_HardBPVector.push_back(hardBP);
        //m_HardBPVector.insert(m_HardBPVector.end(), std::make_pair(hardBP->m_bpAddr, hardBP));
        return;
    }

    // 断点存在返回 TRUE，不存在返回 FALSE
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
    // 断点存在返回 TRUE，不存在返回 FALSE
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

    // 断点存在返回 TRUE，不存在返回 FALSE
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

    // 从链表中删除，并不是取消断点
    void deleteBP(DWORD addr)
    {
        auto m_softIt = m_SoftBPMap.find(addr);

        delete m_softIt->second;
        m_SoftBPMap.erase(m_softIt);

        return;
    }

    // 从数组中删除断点
    // TRUE 删除成功，FALSE 删除失败
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

    // 硬件断点
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

    // 用来判断是否要重置 u 的地址
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
    DWORD m_uAddr = NULL;   // u 命令用的地址
    // 软件断点
    int m_iCount = 0;
    std::map<DWORD, LPSOFT_BP> m_SoftBPMap;     // 地址，软件断点数据
    std::map<DWORD, LPSOFT_BP>::iterator m_softIt;              
    BOOL m_bIsSystemBP = TRUE;

    //
    std::vector<LPHARD_BP> m_HardBPVector;     // 地址，软件断点数据
    std::vector<LPHARD_BP>::iterator m_HardIt;

    //单步步入、单步步过
    BOOL m_bStepIn = FALSE;

    // 跟踪步入的地址
    DWORD m_dwTraceAddr = 0;
    std::fstream *m_TraceFile = NULL;
    BOOL m_bTrace = FALSE;
};



// 保存数据
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