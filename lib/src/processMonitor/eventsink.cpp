#include "stdafx.h" // vs2017 use "pch.h" for vs2019
#include "eventsink.h"

typedef void(__stdcall Callback)(char const * event, char const * process, char const * handle);
extern Callback* callback;

ULONG EventSink::AddRef()
{
	return InterlockedIncrement(&m_lRef);
}

ULONG EventSink::Release()
{
	LONG lRef = InterlockedDecrement(&m_lRef);
	if (lRef == 0)
		delete this;
	return lRef;
}

HRESULT EventSink::QueryInterface(REFIID riid, void** ppv)
{
	if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
	{
		*ppv = (IWbemObjectSink *)this;
		AddRef();
		return WBEM_S_NO_ERROR;
	}
	else return E_NOINTERFACE;
}


HRESULT EventSink::Indicate(long lObjectCount, IWbemClassObject **apObjArray) //cf: https://stackoverflow.com/questions/28897897/c-monitor-process-creation-and-termination-in-windows
{
	HRESULT hr = S_OK;
	_variant_t vtProp;

	for (int i = 0; i < lObjectCount; i++)
	{
		bool CreationOrDeletionEvent = false;
		std::string event;
		_variant_t cn;
		hr = apObjArray[i]->Get(_bstr_t(L"__Class"), 0, &cn, 0, 0);
		if (SUCCEEDED(hr))
		{
			wstring LClassStr(cn.bstrVal);
			if (0 == LClassStr.compare(L"__InstanceDeletionEvent"))
			{
				event = "deletion";
				CreationOrDeletionEvent = true;
			}
			else if (0 == LClassStr.compare(L"__InstanceCreationEvent"))
			{
				event = "creation";
				CreationOrDeletionEvent = true;
			}
			else
			{
				event = "modification";
				CreationOrDeletionEvent = false;
			}
		}
		VariantClear(&cn);

		if (CreationOrDeletionEvent)
		{
			hr = apObjArray[i]->Get(_bstr_t(L"TargetInstance"), 0, &vtProp, 0, 0);
			if (!FAILED(hr))
			{
				IUnknown* str = vtProp;
				hr = str->QueryInterface(IID_IWbemClassObject, reinterpret_cast<void**>(&apObjArray[i]));
				if (SUCCEEDED(hr))
				{
					_bstr_t process;
					_bstr_t handle;
					
					_variant_t cn;
					hr = apObjArray[i]->Get(L"Name", 0, &cn, NULL, NULL);
					if (SUCCEEDED(hr))
					{

						if ((cn.vt == VT_NULL) || (cn.vt == VT_EMPTY))
							process = ((cn.vt == VT_NULL) ? "NULL" : "EMPTY");
						else 
							process = cn.bstrVal;

					}
					VariantClear(&cn);

					hr = apObjArray[i]->Get(L"Handle", 0, &cn, NULL, NULL);
					if (SUCCEEDED(hr))
					{
						if ((cn.vt == VT_NULL) || (cn.vt == VT_EMPTY))
							handle = ((cn.vt == VT_NULL) ? "NULL" : "EMPTY");
						else
							handle = cn.bstrVal;
					}
					VariantClear(&cn);
					callback(event.c_str(),process,handle);
				}
			}
			VariantClear(&vtProp);
		}

	}

	return WBEM_S_NO_ERROR;
}

HRESULT EventSink::SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject __RPC_FAR *pObjParam)
{
	if (lFlags == WBEM_STATUS_COMPLETE)
	{
		//Call complete
	}
	else if (lFlags == WBEM_STATUS_PROGRESS)
	{
		//Call in progress
	}

	return WBEM_S_NO_ERROR;
}
