#include "pch.h"
#include <iostream>
#include "storage.h"
#include "oleacc.h"
#include "tlhelp32.h";
#include "handleapi.h";
#include <string.h>;
#include <sstream>;
#include <windows.h>
#include <atlcomcli.h>
#include <atlbase.h>
#include <servprov.h>
#include "ia2.h"
#include "nvdaHelperRemote.h"
#include "log.h"
#include "backend.h"
#include <windows.h>
#include <chrono>
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "oleacc.lib")
#pragma comment (lib, "oleaut32.lib")
#pragma comment (lib, "C:\\Users\\jetuser\\Desktop\\nvda\\source\\lib\\IAccessible2proxy.lib")

DWORD GetProcessIdByName(const char* name);
HWND FindTopWindow(DWORD pid);
VBufStorage_fieldNode_t* fillVBuf(int docHandle, IAccessible2* pacc, VBufStorage_buffer_t* buffer,
	VBufStorage_controlFieldNode_t* parentNode, VBufStorage_fieldNode_t* previousNode
);
std::pair<std::vector<CComVariant>, HRESULT>
getAccessibleChildren(IAccessible* pacc, long indexOfFirstChild, long maxChildCount);

int main(array<System::String ^> ^args)
{   
    GetForegroundWindow();
    const std::string name = "chrome.exe";
    const char* c = name.c_str();

    DWORD chromePid = GetProcessIdByName(c);
    HWND topChromeWindow = FindTopWindow(chromePid);

    IAccessible* pacc;

    AccessibleObjectFromWindow(topChromeWindow, OBJID_CLIENT, IID_IAccessible, reinterpret_cast<void**>(&pacc));

    VARIANT varChild;
    varChild.vt = VT_I4;
    varChild.lVal = CHILDID_SELF;
    VARIANT accRole;
    BSTR accName;

    long pxLeft, pyTop, pcxWidth, pcyHeight;

    pacc->accLocation(&pxLeft, &pyTop, &pcxWidth, &pcyHeight, varChild);
    pacc->get_accName(varChild, &accName);
    pacc->get_accRole(varChild, &accRole);
      
	IAccessible2* pacc2 = NULL;
	VBufStorage_buffer_t* bufPtr;
	IServiceProvider* pserv = NULL;

	CComVariant varState;
	pacc->get_accState(varChild, &varState);
	VariantClear(&varChild);
	if (varState.vt == VT_I4 && (varState.lVal & STATE_SYSTEM_INVISIBLE)) {
		pacc->Release();
		return 1;
	}

	const IID IID_IAccessible2 = { 0xE89F726E, 0xC4F4, 0x4c19, 0xbb, 0x19, 0xb6, 0x47, 0xd7, 0xfa, 0x84, 0x78 };

	if (pacc->QueryInterface(IID_IServiceProvider, (void**)&pserv) != S_OK) {
		pacc->Release();
		return NULL;
	}
	pacc->Release();
	pserv->QueryService(IID_IAccessible, IID_IAccessible2, (void**)&pacc2);
	pserv->Release();

	long id;

	pacc2->get_uniqueID(&id);

	//std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();	
	//
	//auto buf = new VBufStorage_buffer_t();
	//auto res = fillVBuf((int) topChromeWindow, pacc2, buf, NULL, NULL);
	//
	//std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	//
	//auto secondsElapsed = (end - begin).count() / 1000000000.0;
	//std::cout << "Chrome tree built in " << secondsElapsed << "s";
	//
	//auto firstChild = res->getLastChild();

	std::wstring text;

	
	auto backend = WebKitVBufBackend_t_createInstance((int)topChromeWindow, 0);
	backend->initialize();
	backend->forceUpdate();
	auto len =backend->getTextLength();
	backend->getTextInRange(0, len, text);

	int chromePtr = (int)topChromeWindow;
	int controlFieldNodeId = 0;
	int startOffset = 0;
	int endOffset = 0;

	auto rootControlNode = backend->locateControlFieldNodeAtOffset(-1, &startOffset, &endOffset, &chromePtr, &controlFieldNodeId);
	
	std::vector<VBufStorage_fieldNode_t*> rootNodes = {};

	std::wstring attribs = L"IAccessible::role";
	std::wstring regexp = L"IAccessible\\\\:\\\\:role:(?:43;)";
	int so = 0;
	int eo = backend->getTextLength();

	std::vector<VBufStorage_fieldNode_t*> linksOnCurrentTab = {};

	auto link = backend->findNodeByAttributes(0, VBufStorage_findDirection_forward, attribs, regexp, &so, &eo);

	std::cout << "Backend len is " << backend->getTextLength() << '\n';

	SetConsoleOutputCP(CP_UTF8);
	
	while (link) {		
		int offset = so;

		linksOnCurrentTab.push_back(link);

		std::wstring t;		
		
		link->getTextInRange(0, link->getLength(), t);

		const wchar_t newLine = '\n';

		wprintf(&newLine);
		wprintf(t.c_str());

		link = backend->findNodeByAttributes(offset, VBufStorage_findDirection_forward, attribs, regexp, &so, &eo);	
	}	

	//for (auto next = (VBufStorage_fieldNode_t *) rootControlNode; next; next = next->getNext()) {
	//	std::wstring attr = next->getAttributesString();
	//
	//	rootNodes.push_back(next);
	//}

	std::cout << "end";

	return 0;
}

VBufStorage_fieldNode_t* fillVBuf(int docHandle, IAccessible2* pacc, VBufStorage_buffer_t* buffer,
	VBufStorage_controlFieldNode_t* parentNode, VBufStorage_fieldNode_t* previousNode
) {
	//all IAccessible methods take a variant for childID, get one ready
	CComVariant varChild(CHILDID_SELF);

	// Get role with accRole
	CComVariant varRole;
	pacc->get_accRole(varChild, &varRole);

	if (varRole.vt == VT_I4 && varRole.lVal == ROLE_SYSTEM_COLUMN) {
		// WebKit provides both row and column representations for tables,
		// duplicating the table cells.
		// We never want the column representation.
		return NULL;
	}

	int id;
	if (pacc->get_uniqueID((long*)&id) != S_OK)
		return NULL;

	//Make sure that we don't already know about this object -- protect from loops
	if (buffer->getControlFieldNodeWithIdentifier(docHandle, id) != NULL) {
		return NULL;
	}

	//Add this node to the buffer
	parentNode = buffer->addControlFieldNode(parentNode, previousNode,
		docHandle, id, true);
	nhAssert(parentNode); //new node must have been created
	previousNode = NULL;
	VBufStorage_fieldNode_t* tempNode;

	std::wostringstream s;

	long role = 0;
	if (varRole.vt == VT_EMPTY) {
		s << 0;
	}
	else if (varRole.vt == VT_BSTR) {
		s << varRole.bstrVal;
	}
	else if (varRole.vt == VT_I4) {
		s << varRole.lVal;
		role = varRole.lVal;
	}
	parentNode->addAttribute(L"IAccessible::role", s.str());

	// Get states with accState
	CComVariant varState;
	pacc->get_accState(varChild, &varState);
	int states = varState.lVal;
	//Add each state that is on, as an attrib
	for (int i = 0;i < 32;i++) {
		int state = 1 << i;
		if (state & states) {
			s.str(L"");
			s << L"IAccessible::state_" << state;
			parentNode->addAttribute(s.str(), L"1");
		}
	}

	//Get the child count
	long childCount = 0;
	if (role == ROLE_SYSTEM_COMBOBOX
		|| (role == ROLE_SYSTEM_LIST && !(states & STATE_SYSTEM_READONLY))
		// Editable text fields sometimes have children with no content.
		|| (role == ROLE_SYSTEM_TEXT && states & STATE_SYSTEM_FOCUSABLE)
		) {
		// We don't want this node's children.
		childCount = 0;
	}
	else
		pacc->get_accChildCount(&childCount);

	// Iterate through the children.
	if (childCount > 0) {
		auto [varChildren, accChildrenRes] = getAccessibleChildren(pacc, 0, childCount);
		if (S_OK == accChildrenRes) {
			for (CComVariant& child : varChildren) {
				if (VT_DISPATCH != child.vt) {
					continue;
				}
				CComQIPtr<IAccessible2> childPacc(child.pdispVal);
				if (!childPacc) {
					continue;
				}
				if ((tempNode = fillVBuf(docHandle, childPacc, buffer, parentNode, previousNode)) != NULL) {
					previousNode = tempNode;
				}
			}
		}
	}
	else {

		// No children, so fetch content from this leaf node.
		CComBSTR tempBstr;
		std::wstring content;

		if ((role != ROLE_SYSTEM_TEXT || !(states & STATE_SYSTEM_FOCUSABLE)) && role != ROLE_SYSTEM_COMBOBOX
			&& pacc->get_accName(varChild, &tempBstr) == S_OK && tempBstr) {
			content = tempBstr;
		}
		tempBstr.Empty();
		if (content.empty() && pacc->get_accValue(varChild, &tempBstr) == S_OK && tempBstr) {
			content = tempBstr;
		}
		tempBstr.Empty();
		if (content.empty() && pacc->get_accDescription(varChild, &tempBstr) == S_OK && tempBstr) {
			if (wcsncmp(tempBstr, L"Description: ", 13) == 0) {
				content = &tempBstr[13];
			}
		}
		if (content.empty() && states & STATE_SYSTEM_FOCUSABLE) {
			// This node is focusable, but contains no text.
			// Therefore, add it with a space so that the user can get to it.
			content = L" ";
		}

		if (!content.empty()) {
			if (tempNode = buffer->addTextFieldNode(parentNode, previousNode, content))
				previousNode = tempNode;
		}
	}

	return parentNode;
}

DWORD GetProcessIdByName(const char* name)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    char buf[MAX_PATH] = { 0 };
    size_t charsConverted = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            wcstombs_s(&charsConverted, buf, entry.szExeFile, MAX_PATH);

            //auto r =  std::wstring(entry.szExeFile);
            //std::string str(r.begin(), r.end());
            //std::cout << str << '\n';

            if (_stricmp(buf, name) == 0)
            {
                return entry.th32ProcessID;
            }
        }
    }
    return NULL;
}

HWND FindTopWindow(DWORD pid)
{
    std::pair<HWND, DWORD> params = { 0, pid };

    // Enumerate the windows using a lambda to process each window
    BOOL bResult = EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL
        {
            auto pParams = (std::pair<HWND, DWORD>*)(lParam);

            DWORD processId;
            if (GetWindowThreadProcessId(hwnd, &processId) && processId == pParams->second)
            {
                // Stop enumerating
                SetLastError(-1);
                pParams->first = hwnd;
                return FALSE;
            }

            // Continue enumerating
            return TRUE;
        }, (LPARAM)&params);

    if (!bResult && GetLastError() == -1 && params.first)
    {
        return params.first;
    }

    return 0;
}