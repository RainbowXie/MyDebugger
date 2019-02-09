#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <map>
#include <queue>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
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
    int nSequenceNumber;     // ���
    eType m_type;                   // �ϵ�����
    DWORD m_bpAddr;     // �ϵ��ַ
    char m_oldCode;              // �ϵ�ԭ����ָ��
    int m_bActive;         // �Ƿ����öϵ�
    BOOL m_bCurrentBP; // �Ƿ��ǵ�ǰ�Ķϵ㣬��������ϵ�
}SOFT_BP, *LPSOFT_BP;

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

//////////////////////////////////////////////////////////////////////////
//���������õõ�������
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

    // �ϵ���ڷ��� TRUE�������ڷ��� FALSE
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

    // ��������ɾ����������ȡ���ϵ�
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

    // Ӳ���ϵ�
    
private:
    // ����ϵ�
    int m_iCount;
    std::map<DWORD, LPSOFT_BP> m_SoftBPMap;     // ��ַ������ϵ�����
    std::map<DWORD, LPSOFT_BP>::iterator it;              
    BOOL m_bIsSystemBP = TRUE;


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
BOOL setHardBP(HANDLE hThread, DWORD dwAddr, DWORD dwLen, eType BPType);

BOOL analyzeInstruction(LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
std::queue<std::string>* getUserInput();

void doG(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBP(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBPL(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBPC(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);
void doBH(HANDLE hProcess, LPDEBUG_EVENT pDe, std::queue<std::string>* qu);



