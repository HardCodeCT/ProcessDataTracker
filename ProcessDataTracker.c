// Define NDIS version before including any headers
#define NDIS630 1
#define NDIS_SUPPORT_NDIS630 1

#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>

#pragma warning(push)
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4996) // deprecated function warnings

// Device name for IOCTL communication
#define DEVICE_NAME L"\\Device\\ProcessDataTracker"
#define SYMLINK_NAME L"\\DosDevices\\ProcessDataTracker"

// IOCTL codes for communication with user-mode
#define IOCTL_GET_PROCESS_STATS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESET_STATS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Separate GUIDs for each callout - must match user-mode
DEFINE_GUID(PROCESS_TRACKER_CALLOUT_ALE_V4_GUID,
    0x87654321, 0x4321, 0x4321, 0x43, 0x21, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21);

DEFINE_GUID(PROCESS_TRACKER_CALLOUT_OUTBOUND_V4_GUID,
    0x87654322, 0x4321, 0x4321, 0x43, 0x21, 0x21, 0x09, 0x87, 0x65, 0x43, 0x22);

DEFINE_GUID(PROCESS_TRACKER_CALLOUT_INBOUND_V4_GUID,
    0x87654323, 0x4321, 0x4321, 0x43, 0x21, 0x21, 0x09, 0x87, 0x65, 0x43, 0x23);

// Structure for communicating stats to user-mode
typedef struct _PROCESS_STATS_KERNEL {
    UINT32 ProcessId;
    UINT64 BytesSent;
    UINT64 BytesReceived;
    UINT64 PacketsSent;
    UINT64 PacketsReceived;
} PROCESS_STATS_KERNEL, *PPROCESS_STATS_KERNEL;

// Flow context structure
typedef struct _FLOW_CONTEXT {
    UINT32 ProcessId;
} FLOW_CONTEXT, *PFLOW_CONTEXT;

// Process stats entry
typedef struct _STATS_ENTRY {
    LIST_ENTRY ListEntry;
    UINT32 ProcessId;
    UINT64 BytesSent;
    UINT64 BytesReceived;
    UINT64 PacketsSent;
    UINT64 PacketsReceived;
} STATS_ENTRY, *PSTATS_ENTRY;

// Global variables
UINT32 g_CalloutIdAleV4 = 0;
UINT32 g_CalloutIdOutboundV4 = 0;
UINT32 g_CalloutIdInboundV4 = 0;
PDEVICE_OBJECT g_DeviceObject = NULL;

// Hash table for process statistics
#define HASH_TABLE_SIZE 256
LIST_ENTRY g_StatsHashTable[HASH_TABLE_SIZE];
KSPIN_LOCK g_StatsLock;

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DeviceCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DeviceControl;

NTSTATUS RegisterCallouts(PDEVICE_OBJECT deviceObject);
VOID UnregisterCallouts(VOID);

// Callout functions - using correct signatures for FWPS_CALLOUT_CLASSIFY_FN2
VOID NTAPI ClassifyFnAleV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER2* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

VOID NTAPI ClassifyFnOutboundV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER2* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

VOID NTAPI ClassifyFnInboundV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER2* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER2* filter
);

VOID NTAPI FlowDeleteFnAleV4(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
);

// Helper functions
UINT32 HashProcessId(UINT32 processId);
VOID UpdateProcessStats(UINT32 processId, UINT64 bytes, BOOLEAN isOutbound);
PSTATS_ENTRY FindOrCreateStatsEntry(UINT32 processId);

// Driver Entry Point
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PUNICODE_STRING registryPath
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    ULONG i;
    
    UNREFERENCED_PARAMETER(registryPath);
    
    DbgPrint("ProcessDataTracker: DriverEntry called\n");
    
    // Initialize hash table and lock
    KeInitializeSpinLock(&g_StatsLock);
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        InitializeListHead(&g_StatsHashTable[i]);
    }
    
    // Create device object
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = IoCreateDevice(
        driverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcessDataTracker: Failed to create device: 0x%X\n", status);
        return status;
    }
    
    // Create symbolic link
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcessDataTracker: Failed to create symbolic link: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }
    
    // Set up dispatch routines
    driverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    driverObject->DriverUnload = DriverUnload;
    
    // Register callouts
    status = RegisterCallouts(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcessDataTracker: Failed to register callouts: 0x%X\n", status);
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }
    
    DbgPrint("ProcessDataTracker: Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

// Driver Unload
VOID DriverUnload(_In_ PDRIVER_OBJECT driverObject)
{
    UNICODE_STRING symlinkName;
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PSTATS_ENTRY statsEntry;
    ULONG i;
    
    UNREFERENCED_PARAMETER(driverObject);
    
    DbgPrint("ProcessDataTracker: DriverUnload called\n");
    
    // Unregister callouts
    UnregisterCallouts();
    
    // Clean up stats hash table
    KeAcquireSpinLock(&g_StatsLock, &oldIrql);
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        while (!IsListEmpty(&g_StatsHashTable[i])) {
            entry = RemoveHeadList(&g_StatsHashTable[i]);
            statsEntry = CONTAINING_RECORD(entry, STATS_ENTRY, ListEntry);
            ExFreePoolWithTag(statsEntry, 'STAT');
        }
    }
    KeReleaseSpinLock(&g_StatsLock, oldIrql);
    
    // Delete symbolic link and device
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }
    
    DbgPrint("ProcessDataTracker: Driver unloaded\n");
}

// Register WFP callouts
NTSTATUS RegisterCallouts(PDEVICE_OBJECT deviceObject)
{
    NTSTATUS status;
    FWPS_CALLOUT2 callout = { 0 };
    
    // Register ALE V4 callout
    callout.calloutKey = PROCESS_TRACKER_CALLOUT_ALE_V4_GUID;
    callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN2)ClassifyFnAleV4;
    callout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN2)NotifyFn;
    callout.flowDeleteFn = FlowDeleteFnAleV4;
    
    status = FwpsCalloutRegister2(deviceObject, &callout, &g_CalloutIdAleV4);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcessDataTracker: Failed to register ALE V4 callout: 0x%X\n", status);
        return status;
    }
    
    // Register outbound V4 callout
    callout.calloutKey = PROCESS_TRACKER_CALLOUT_OUTBOUND_V4_GUID;
    callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN2)ClassifyFnOutboundV4;
    callout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN2)NotifyFn;
    callout.flowDeleteFn = NULL;
    
    status = FwpsCalloutRegister2(deviceObject, &callout, &g_CalloutIdOutboundV4);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcessDataTracker: Failed to register outbound V4 callout: 0x%X\n", status);
        FwpsCalloutUnregisterById0(g_CalloutIdAleV4);
        return status;
    }
    
    // Register inbound V4 callout
    callout.calloutKey = PROCESS_TRACKER_CALLOUT_INBOUND_V4_GUID;
    callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN2)ClassifyFnInboundV4;
    callout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN2)NotifyFn;
    callout.flowDeleteFn = NULL;
    
    status = FwpsCalloutRegister2(deviceObject, &callout, &g_CalloutIdInboundV4);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProcessDataTracker: Failed to register inbound V4 callout: 0x%X\n", status);
        FwpsCalloutUnregisterById0(g_CalloutIdAleV4);
        FwpsCalloutUnregisterById0(g_CalloutIdOutboundV4);
        return status;
    }
    
    DbgPrint("ProcessDataTracker: All callouts registered successfully\n");
    return STATUS_SUCCESS;
}

// Unregister callouts
VOID UnregisterCallouts(VOID)
{
    if (g_CalloutIdAleV4 != 0) {
        FwpsCalloutUnregisterById0(g_CalloutIdAleV4);
    }
    if (g_CalloutIdOutboundV4 != 0) {
        FwpsCalloutUnregisterById0(g_CalloutIdOutboundV4);
    }
    if (g_CalloutIdInboundV4 != 0) {
        FwpsCalloutUnregisterById0(g_CalloutIdInboundV4);
    }
}

// ALE Classify Function
VOID NTAPI ClassifyFnAleV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER2* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    NTSTATUS status;
    PFLOW_CONTEXT context;
    UINT64 flowId;
    
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    
    // Only set flow context if not already set
    if (flowContext == 0 && FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        context = (PFLOW_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FLOW_CONTEXT), 'FCTX');
        if (context) {
            context->ProcessId = (UINT32)inMetaValues->processId;
            
            // Get the flow ID
            flowId = inMetaValues->flowHandle;
            
            // Associate context with flow using FwpsFlowAssociateContext0
            status = FwpsFlowAssociateContext0(
                flowId,
                FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4,
                g_CalloutIdAleV4,
                (UINT64)context
            );
            
            if (!NT_SUCCESS(status)) {
                DbgPrint("ProcessDataTracker: Failed to associate flow context: 0x%X\n", status);
                ExFreePoolWithTag(context, 'FCTX');
            } else {
                DbgPrint("ProcessDataTracker: Set flow context for PID %u\n", context->ProcessId);
            }
        }
    }
    
    classifyOut->actionType = FWP_ACTION_PERMIT;
}

// Outbound Transport Classify Function
VOID NTAPI ClassifyFnOutboundV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER2* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    PFLOW_CONTEXT context;
    PNET_BUFFER_LIST netBufferList;
    PNET_BUFFER netBuffer;
    UINT32 pid;
    UINT64 bytes;
    
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    
    // Use the flowContext parameter directly - it contains our context pointer
    context = (PFLOW_CONTEXT)flowContext;
    
    if (context && layerData) {
        pid = context->ProcessId;
        bytes = 0;
        
        netBufferList = (PNET_BUFFER_LIST)layerData;
        netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
        
        while (netBuffer) {
            bytes += NET_BUFFER_DATA_LENGTH(netBuffer);
            netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
        }
        
        if (bytes > 0) {
            UpdateProcessStats(pid, bytes, TRUE); // Outbound
        }
    }
    
    classifyOut->actionType = FWP_ACTION_PERMIT;
}

// Inbound Transport Classify Function
VOID NTAPI ClassifyFnInboundV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER2* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    PFLOW_CONTEXT context;
    PNET_BUFFER_LIST netBufferList;
    PNET_BUFFER netBuffer;
    UINT32 pid;
    UINT64 bytes;
    
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    
    // Use the flowContext parameter directly - it contains our context pointer
    context = (PFLOW_CONTEXT)flowContext;
    
    if (context && layerData) {
        pid = context->ProcessId;
        bytes = 0;
        
        netBufferList = (PNET_BUFFER_LIST)layerData;
        netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
        
        while (netBuffer) {
            bytes += NET_BUFFER_DATA_LENGTH(netBuffer);
            netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
        }
        
        if (bytes > 0) {
            UpdateProcessStats(pid, bytes, FALSE); // Inbound
        }
    }
    
    classifyOut->actionType = FWP_ACTION_PERMIT;
}

// Notify Function
NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER2* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    
    return STATUS_SUCCESS;
}

// Flow Delete Function for ALE
VOID NTAPI FlowDeleteFnAleV4(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
)
{
    PFLOW_CONTEXT context;
    
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    
    context = (PFLOW_CONTEXT)flowContext;
    if (context) {
        FwpsFlowRemoveContext0(flowContext, FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4, calloutId);
        ExFreePoolWithTag(context, 'FCTX');
    }
}

// Hash function for process ID
UINT32 HashProcessId(UINT32 processId)
{
    return processId % HASH_TABLE_SIZE;
}

// Find or create stats entry
PSTATS_ENTRY FindOrCreateStatsEntry(UINT32 processId)
{
    UINT32 hash = HashProcessId(processId);
    PLIST_ENTRY entry;
    PSTATS_ENTRY statsEntry;
    
    // Search for existing entry
    for (entry = g_StatsHashTable[hash].Flink;
         entry != &g_StatsHashTable[hash];
         entry = entry->Flink) {
        statsEntry = CONTAINING_RECORD(entry, STATS_ENTRY, ListEntry);
        if (statsEntry->ProcessId == processId) {
            return statsEntry;
        }
    }
    
    // Create new entry
    statsEntry = (PSTATS_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(STATS_ENTRY), 'STAT');
    if (statsEntry == NULL) {
        return NULL;
    }
    
    RtlZeroMemory(statsEntry, sizeof(STATS_ENTRY));
    statsEntry->ProcessId = processId;
    InsertHeadList(&g_StatsHashTable[hash], &statsEntry->ListEntry);
    
    return statsEntry;
}

// Update process statistics (also increments packets)
VOID UpdateProcessStats(UINT32 processId, UINT64 bytes, BOOLEAN isOutbound)
{
    KIRQL oldIrql;
    PSTATS_ENTRY statsEntry;
    
    if (processId == 0) return;
    
    KeAcquireSpinLock(&g_StatsLock, &oldIrql);
    
    statsEntry = FindOrCreateStatsEntry(processId);
    if (statsEntry != NULL) {
        if (isOutbound) {
            statsEntry->BytesSent += bytes;
            statsEntry->PacketsSent += 1;
        } else {
            statsEntry->BytesReceived += bytes;
            statsEntry->PacketsReceived += 1;
        }
    }
    
    KeReleaseSpinLock(&g_StatsLock, oldIrql);
}

// Device Create/Close handler
NTSTATUS DeviceCreateClose(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
)
{
    UNREFERENCED_PARAMETER(deviceObject);
    
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

// Device Control handler
NTSTATUS DeviceControl(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
)
{
    PIO_STACK_LOCATION irpStack;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;
    KIRQL oldIrql;
    ULONG i;
    
    UNREFERENCED_PARAMETER(deviceObject);
    
    irpStack = IoGetCurrentIrpStackLocation(irp);
    
    switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_GET_PROCESS_STATS: {
            PPROCESS_STATS_KERNEL outputBuffer = (PPROCESS_STATS_KERNEL)irp->AssociatedIrp.SystemBuffer;
            ULONG outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
            ULONG maxEntries = outputBufferLength / sizeof(PROCESS_STATS_KERNEL);
            ULONG entryCount = 0;
            
            KeAcquireSpinLock(&g_StatsLock, &oldIrql);
            
            for (i = 0; i < HASH_TABLE_SIZE && entryCount < maxEntries; i++) {
                PLIST_ENTRY entry;
                for (entry = g_StatsHashTable[i].Flink;
                     entry != &g_StatsHashTable[i] && entryCount < maxEntries;
                     entry = entry->Flink) {
                    PSTATS_ENTRY statsEntry = CONTAINING_RECORD(entry, STATS_ENTRY, ListEntry);
                    outputBuffer[entryCount].ProcessId = statsEntry->ProcessId;
                    outputBuffer[entryCount].BytesSent = statsEntry->BytesSent;
                    outputBuffer[entryCount].BytesReceived = statsEntry->BytesReceived;
                    outputBuffer[entryCount].PacketsSent = statsEntry->PacketsSent;
                    outputBuffer[entryCount].PacketsReceived = statsEntry->PacketsReceived;
                    entryCount++;
                }
            }
            
            KeReleaseSpinLock(&g_StatsLock, oldIrql);
            
            bytesReturned = entryCount * sizeof(PROCESS_STATS_KERNEL);
            status = STATUS_SUCCESS;
            break;
        }
        
        case IOCTL_RESET_STATS: {
            PLIST_ENTRY entry;
            PSTATS_ENTRY statsEntry;
            
            KeAcquireSpinLock(&g_StatsLock, &oldIrql);
            
            for (i = 0; i < HASH_TABLE_SIZE; i++) {
                while (!IsListEmpty(&g_StatsHashTable[i])) {
                    entry = RemoveHeadList(&g_StatsHashTable[i]);
                    statsEntry = CONTAINING_RECORD(entry, STATS_ENTRY, ListEntry);
                    ExFreePoolWithTag(statsEntry, 'STAT');
                }
            }
            
            KeReleaseSpinLock(&g_StatsLock, oldIrql);
            
            status = STATUS_SUCCESS;
            break;
        }
        
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    
    return status;
}

#pragma warning(pop)
