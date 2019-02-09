#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <map>
#include <queue>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
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
    int nSequenceNumber;     // 序号
    eType m_type;                   // 断点类型
    DWORD m_bpAddr;     // 断点地址
    char m_oldCode;              // 断点原来的指令
    int m_bActive;         // 是否启用断点
    BOOL m_bCurrentBP; // 是否是当前的断点，用于重设断点
}SOFT_BP, *LPSOFT_BP;

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

//////////////////////////////////////////////////////////////////////////
//保存所有用得到的数据
//
//////////////////////////////////////////////////////////////////////////
class CDebugData
{
public:
    CDebugData()
    {
        it = m_SoftBPMap.begin();
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
        softBP->nSequenceNumber = m_iCount;
        softBP->m_bCurrentBP = FALSE;
        m_SoftBPMap.insert(m_SoftBPMap.end(), std::make_pair(softBP->m_bpAddr, softBP));
        return;
    }

    // 断点存在返回 TRUE，不存在返回 FALSE
    BOOL isSoftBPExist(DWORD addr)
    {
        auto it = m_SoftBPMap.find(addr);

        if (it == m_SoftBPMap.end())
        {
            return FALSE;
        }

        return TRUE;
    }

    LPSOFT_BP getSoftBP(DWORD addr)
    {
        std::map<DWORD, LPSOFT_BP>::iterator it;
        it = m_SoftBPMap.find(addr);
        return it->second;
    }

    LPSOFT_BP getFirstSoftBP()
    {
        it = m_SoftBPMap.begin();
        return it->second;
    }
    LPSOFT_BP getNextSoftBP()
    {
        it++;
        if (m_SoftBPMap.end() == it)
        {
            return NULL;
        }
        return it->second;
    }

    // 从链表中删除，并不是取消断点
    void deleteBP(DWORD addr)
    {
        auto it = m_SoftBPMap.find(addr);

        m_SoftBPMap.erase(it);

        return;
    }

    LPSOFT_BP getCurrentSoftBP()
    {
        auto it = m_SoftBPMap.begin();
        for (; it != m_SoftBPMap.end();it++)
        {
            if (TRUE == it->second->m_bCurrentBP)
            {
                it->second->m_bCurrentBP = FALSE;
                return it->second;
            }     
        }
        return NULL;
    }

    // 硬件断点
    
private:
    // 软件断点
    int m_iCount;
    std::map<DWORD, LPSOFT_BP> m_SoftBPMap;     // 地址，软件断点数据
    std::map<DWORD, LPSOFT_BP>::iterator it;              
    BOOL m_bIsSystemBP = TRUE;


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
BOOL setHardBP(HANDLE hThread, DWORD dwAddr, DWORD dwLen, eType BPType);

BOOL analyzeInstruction(LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
std::queue<std::string>* getUserInput();

void doG(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBP(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBPL(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBPC(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBH(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);



