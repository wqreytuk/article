#include <ntddk.h>
#include <dontuse.h>

#define DRIVER_TAG 'dcba'

UNICODE_STRING g_RegistryPath;

void SampleUnload(_In_ PDRIVER_OBJECT DriverObject);

extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	(DriverObject);
	(RegistryPath);
	DriverObject->DriverUnload = SampleUnload;
	KdPrint(("Sample driver initialized successfully\n"));

	g_RegistryPath.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool,RegistryPath->Length, DRIVER_TAG);
	if (nullptr == g_RegistryPath.Buffer) {
		KdPrint(("Failed to allocate memory\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	g_RegistryPath.MaximumLength = RegistryPath->MaximumLength;
	RtlCopyUnicodeString(&g_RegistryPath, RegistryPath);

	KdPrint(("Original registry path: %wZ\n", RegistryPath));
	KdPrint(("Copied registry path: %wZ\n", &g_RegistryPath));

	return STATUS_SUCCESS; 
}

void SampleUnload(_In_ PDRIVER_OBJECT DriverObject) {
	(DriverObject);
	KdPrint(("Sample driver Unload called\n"));
}
