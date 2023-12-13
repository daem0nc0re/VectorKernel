#include <ntifs.h>

#define DRIVER_PREFIX "CreateTokenDrv: "
#define DEVICE_PATH L"\\Device\\CreateToken"
#define SYMLINK_PATH L"\\??\\CreateToken"
#define DRIVER_TAG 'lnKV'

#pragma warning(disable: 4996) // This warning is caused when use old ExAllocatePoolWithTag() API.

//
// Ioctl code definition
//
#define IOCTL_CREATE_SYSTEM_TOKEN CTL_CODE(0x8000, 0x0A00, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Windows definition
//
typedef enum _SE_GROUP_ATTRIBUTES
{
	SE_GROUP_MANDATORY = 0x00000001L,
	SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L,
	SE_GROUP_ENABLED = 0x00000004L,
	SE_GROUP_OWNER = 0x00000008L,
	SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L,
	SE_GROUP_INTEGRITY = 0x00000020L,
	SE_GROUP_INTEGRITY_ENABLED = 0x00000040L,
	SE_GROUP_RESOURCE = 0x20000000L,
	SE_GROUP_LOGON_ID = 0xC0000000L
} SE_GROUP_ATTRIBUTES;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	SystemLocksInformation, // q: RTL_PROCESS_LOCKS
	SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
	SystemPagedPoolInformation, // not implemented
	SystemNonPagedPoolInformation, // not implemented
	SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
	SystemVdmBopInformation, // not implemented // 20
	SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
	SystemLoadGdiDriverInformation, // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
	SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
	SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
	SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
	SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
	SystemComPlusPackage, // q; s: ULONG
	SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
	SystemObjectSecurityMode, // q: ULONG // 70
	SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
	SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
	SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
	SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
	SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
	SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation, // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
	SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
	SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
	SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
	SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
	SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
	SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
	SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
	SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
	SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
	SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
	SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
	SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
	SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
	SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
	SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
	SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
	SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
	SystemBadPageInformation,
	SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
	SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
	SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
	SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
	SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
	SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
	SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
	SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
	SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
	SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
	SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
	SystemCriticalProcessErrorLogInformation,
	SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
	SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
	SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
	SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
	SystemBootMetadataInformation, // 150
	SystemSoftRebootInformation, // q: ULONG
	SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
	SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
	SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
	SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
	SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
	SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
	SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
	SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
	SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
	SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
	SystemCodeIntegrityPolicyInformation, // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
	SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
	SystemAllowedCpuSetsInformation, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
	SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
	SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
	SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
	SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
	SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
	SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
	SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
	SystemInterruptSteeringInformation, // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
	SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
	SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
	SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
	SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
	SystemControlFlowTransition, // (Warbird/Encrypt/Decrypt/Execute)
	SystemKernelDebuggingAllowed, // s: ULONG
	SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
	SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
	SystemCodeIntegrityPoliciesFullInformation,
	SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
	SystemIntegrityQuotaInformation,
	SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
	SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
	SystemSecureDumpEncryptionInformation,
	SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
	SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
	SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
	SystemFirmwareBootPerformanceInformation,
	SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
	SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
	SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
	SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
	SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
	SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
	SystemCodeIntegrityUnlockModeInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
	SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
	SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
	SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
	SystemCodeIntegritySyntheticCacheInformation,
	SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
	SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
	SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
	SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
	SystemSpacesBootInformation, // since 20H2
	SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
	SystemWheaIpmiHardwareInformation,
	SystemDifSetRuleClassInformation, // SYSTEM_DIF_VOLATILE_INFORMATION
	SystemDifClearRuleClassInformation,
	SystemDifApplyPluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
	SystemDifRemovePluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION // 220
	SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
	SystemBuildVersionInformation, // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
	SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege)
	SystemCodeIntegrityAddDynamicStore,
	SystemCodeIntegrityClearDynamicStores,
	SystemDifPoolTrackingInformation,
	SystemPoolZeroingInformation, // q: SYSTEM_POOL_ZEROING_INFORMATION
	SystemDpcWatchdogInformation, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
	SystemDpcWatchdogInformation2, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
	SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
	SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
	SystemXfgCheckFailureInformation, // q: SYSTEM_XFG_FAILURE_INFORMATION
	SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
	SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
	SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
	SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
	SystemSecureKernelDebuggerInformation,
	SystemOriginalImageFeatureInformation, // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef struct _SEP_TOKEN_PRIVILEGES
{
	ULONGLONG Present;
	ULONGLONG Enabled;
	ULONGLONG EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, *PSEP_TOKEN_PRIVILEGES;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY
{
	LONG BeginAddress;
	LONG EndAddress;
	union {
		LONG UnwindInfoAddress;
		LONG UnwindData;
	} DUMMYUNIONNAME;
} IMAGE_RUNTIME_FUNCTION_ENTRY, *PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_SECTION_HEADER
{
	CHAR Name[8];
	union {
		LONG PhysicalAddress;
		LONG VirtualSize;
	} Misc;
	LONG VirtualAddress;
	LONG SizeOfRawData;
	LONG PointerToRawData;
	LONG PointerToRelocations;
	LONG PointerToLinenumbers;
	SHORT  NumberOfRelocations;
	SHORT  NumberOfLinenumbers;
	LONG Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	PVOID Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _IMAGE_DOS_HEADER
{
	USHORT e_magic;
	USHORT e_cblp;
	USHORT e_cp;
	USHORT e_crlc;
	USHORT e_cparhdr;
	USHORT e_minalloc;
	USHORT e_maxalloc;
	USHORT e_ss;
	USHORT e_sp;
	USHORT e_csum;
	USHORT e_ip;
	USHORT e_cs;
	USHORT e_lfarlc;
	USHORT e_ovno;
	USHORT e_res[4];
	USHORT e_oemid;
	USHORT e_oeminfo;
	USHORT e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
	SHORT Machine;
	SHORT NumberOfSections;
	LONG TimeDateStamp;
	LONG PointerToSymbolTable;
	LONG NumberOfSymbols;
	SHORT SizeOfOptionalHeader;
	SHORT Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
	LONG VirtualAddress;
	LONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	SHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	LONG SizeOfCode;
	LONG SizeOfInitializedData;
	LONG SizeOfUninitializedData;
	LONG AddressOfEntryPoint;
	LONG BaseOfCode;
	ULONG64 ImageBase;
	LONG SectionAlignment;
	LONG FileAlignment;
	SHORT MajorOperatingSystemVersion;
	SHORT MinorOperatingSystemVersion;
	SHORT MajorImageVersion;
	SHORT MinorImageVersion;
	SHORT MajorSubsystemVersion;
	SHORT MinorSubsystemVersion;
	LONG Win32VersionValue;
	LONG SizeOfImage;
	LONG SizeOfHeaders;
	LONG CheckSum;
	SHORT Subsystem;
	SHORT DllCharacteristics;
	ULONG64 SizeOfStackReserve;
	ULONG64 SizeOfStackCommit;
	ULONG64 SizeOfHeapReserve;
	ULONG64 SizeOfHeapCommit;
	LONG LoaderFlags;
	LONG NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS64
{
	LONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
	ULONG Characteristics;
	ULONG TimeDateStamp;
	USHORT MajorVersion;
	USHORT MinorVersion;
	ULONG Name;
	ULONG Base;
	ULONG NumberOfFunctions;
	ULONG NumberOfNames;
	ULONG AddressOfFunctions;
	ULONG AddressOfNames;
	ULONG AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

//
// Function type definition
//
typedef NTSTATUS (NTAPI *PZwQuerySystemInformation)(
	_In_	  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID SystemInformation,
	_In_	  ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);
typedef NTSTATUS (NTAPI *PZwCreateToken)(
	_Out_ PHANDLE TokenHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ TOKEN_TYPE Type,
	_In_ PLUID AuthenticationId,
	_In_ PLARGE_INTEGER ExpirationTime,
	_In_ PTOKEN_USER User,
	_In_ PTOKEN_GROUPS Groups,
	_In_ PTOKEN_PRIVILEGES Privileges,
	_In_opt_ PTOKEN_OWNER Owner,
	_In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
	_In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
	_In_ PTOKEN_SOURCE Source
);

//
// API address storage
//
PZwCreateToken ZwCreateToken = nullptr;

//
// Prototypes
//
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS OnCreateClose(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);
NTSTATUS OnDeviceControl(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);
NTSTATUS CreateElavatedToken(_Out_ PHANDLE pTokenHandle);
PVOID GetKernelBase();
LONG GetSystcallNumber(_In_ const PCHAR syscallName);
PVOID GetZwCreateTokenBase();
LONG GetCurrentTokenSessionId();

//
// Driver routines
//
extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS ntstatus = STATUS_FAILED_DRIVER_ENTRY;
	PDEVICE_OBJECT pDeviceObject = nullptr;

	do
	{
		UNICODE_STRING devicePath = RTL_CONSTANT_STRING(DEVICE_PATH);
		UNICODE_STRING symlinkPath = RTL_CONSTANT_STRING(SYMLINK_PATH);

		ZwCreateToken = (PZwCreateToken)GetZwCreateTokenBase();

		if (ZwCreateToken == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve ZwCreateToken() API.\n"));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "ZwCreateToken() API is at 0x%p.\n", (PVOID)ZwCreateToken));
		}

		ntstatus = ::IoCreateDevice(
			DriverObject,
			NULL,
			&devicePath,
			FILE_DEVICE_UNKNOWN,
			NULL,
			FALSE,
			&pDeviceObject);

		if (!NT_SUCCESS(ntstatus))
		{
			pDeviceObject = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to create device (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		ntstatus = ::IoCreateSymbolicLink(&symlinkPath, &devicePath);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to create symbolic link (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		DriverObject->DriverUnload = DriverUnload;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreateClose;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;

		KdPrint((DRIVER_PREFIX "Driver is loaded successfully.\n"));
	} while (false);

	if (!NT_SUCCESS(ntstatus) && (pDeviceObject != nullptr))
		::IoDeleteDevice(pDeviceObject);

	return ntstatus;
}


void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symlinkPath = RTL_CONSTANT_STRING(SYMLINK_PATH);
	::IoDeleteSymbolicLink(&symlinkPath);
	::IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint((DRIVER_PREFIX "Driver is unloaded.\n"));
}


NTSTATUS OnCreateClose(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS ntstatus = STATUS_SUCCESS;
	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = 0u;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}


NTSTATUS OnDeviceControl(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS ntstatus = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR info = NULL;
	PIO_STACK_LOCATION irpSp = ::IoGetCurrentIrpStackLocation(Irp);
	auto& dic = irpSp->Parameters.DeviceIoControl;
	HANDLE hNewToken = nullptr;
	PEPROCESS pCurrentProcess = nullptr;
	PACCESS_TOKEN pCurrentToken = nullptr;
	PSEP_TOKEN_PRIVILEGES pSepToken = nullptr;
	LONG sessionId = 0;

	switch (dic.IoControlCode)
	{
	case IOCTL_CREATE_SYSTEM_TOKEN:
		if (dic.OutputBufferLength < sizeof(HANDLE))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Output buffer is too small.\n"));
			break;
		}

		ntstatus = CreateElavatedToken(&hNewToken);

		if (!NT_SUCCESS(ntstatus))
			break;

		// Enables following privileges for caller to easily use the created token:
		//
		// * SeAssignPrimaryTokenPrivilege
		// * SeIncreaseQuotaPrivilege
		// * SeImpersonatePrivilege
		pCurrentProcess = ::IoGetCurrentProcess();
		pCurrentToken = ::PsReferencePrimaryToken(pCurrentProcess);

		pSepToken = (PSEP_TOKEN_PRIVILEGES)((ULONG_PTR)pCurrentToken + 0x40);
		pSepToken->Present |= 0x0000000020000028ULL;
		pSepToken->Enabled |= 0x0000000020000028ULL;

		::PsDereferencePrimaryToken(pCurrentToken);

		// Update token session ID to current process's one
		sessionId = GetCurrentTokenSessionId();

		if (sessionId > 0)
		{
			KdPrint((DRIVER_PREFIX "Current process session ID is %d.\n", sessionId));

			ntstatus = ::ZwSetInformationToken(
				hNewToken,
				TokenSessionId,
				&sessionId,
				sizeof(LONG));

			if (!NT_SUCCESS(ntstatus))
			{
				KdPrint((DRIVER_PREFIX "Failed to adjust token session ID.\n"));
				ntstatus = STATUS_SUCCESS;
			}
			else
			{
				KdPrint((DRIVER_PREFIX "Token session ID is adjusted successfully.\n"));
			}
		}
		else if (sessionId == -1)
		{
			KdPrint((DRIVER_PREFIX "Failed to get current process session ID.\n"));
		}

		*(HANDLE*)Irp->AssociatedIrp.SystemBuffer = hNewToken;
		info = sizeof(HANDLE);
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}


//
// Helper functions
//
PVOID GetKernelBase()
{
	NTSTATUS ntstatus = STATUS_INFO_LENGTH_MISMATCH;
	PVOID pNtoskrnl = nullptr;
	PVOID pInfoBuffer = nullptr;
	ULONG nInfoLength = 0x1000u;
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
	PZwQuerySystemInformation ZwQuerySystemInformation = (PZwQuerySystemInformation)::MmGetSystemRoutineAddress(&routineName);

	if (ZwQuerySystemInformation == nullptr)
	{
		KdPrint((DRIVER_PREFIX "Failed to resolve %wZ() API.\n", routineName));
		return nullptr;
	}
	else
	{
		KdPrint((DRIVER_PREFIX "%wZ() API is at 0x%p.\n", routineName, (PVOID)ZwQuerySystemInformation));
	}

	while (ntstatus == STATUS_INFO_LENGTH_MISMATCH)
	{
		pInfoBuffer = ::ExAllocatePool2(POOL_FLAG_NON_PAGED, nInfoLength, (ULONG)DRIVER_TAG);
		// pInfoBuffer = ::ExAllocatePoolWithTag(NonPagedPool, nInfoLength, (ULONG)DRIVER_TAG);

		if (pInfoBuffer == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate buffer for %wZ() API.\n", routineName));
			break;
		}

		ntstatus = ZwQuerySystemInformation(SystemModuleInformation, pInfoBuffer, nInfoLength, &nInfoLength);

		if (!NT_SUCCESS(ntstatus))
		{
			::ExFreePoolWithTag(pInfoBuffer, (ULONG)DRIVER_TAG);
			pInfoBuffer = nullptr;
		}
	}

	if (NT_SUCCESS(ntstatus) && (pInfoBuffer != nullptr))
	{
		auto nModules = ((PRTL_PROCESS_MODULES)pInfoBuffer)->NumberOfModules;

		for (auto idx = 0u; idx < nModules; idx++)
		{
			auto entry = ((PRTL_PROCESS_MODULES)pInfoBuffer)->Modules[idx];
			auto moduleName = (PCHAR)((ULONG_PTR)&entry.FullPathName + entry.OffsetToFileName);

			if (moduleName == nullptr)
				continue;

			if (::_strnicmp(moduleName, const_cast<PCHAR>("ntoskrnl.exe"), 12u) == 0)
			{
				pNtoskrnl = entry.ImageBase;
				break;
			}
		}

		::ExFreePoolWithTag(pInfoBuffer, (ULONG)DRIVER_TAG);
		pInfoBuffer = nullptr;
	}

	KdPrint((DRIVER_PREFIX "ntoskrnl.exe is at 0x%p.\n", pNtoskrnl));

	return pNtoskrnl;
}


LONG GetSystcallNumber(_In_ const PCHAR syscallName)
{
	HANDLE hSection = nullptr;
	HANDLE hSystem = nullptr;
	LONG nSyscallNumber = -1L;

	do
	{
		NTSTATUS ntstatus;
		PVOID pSectionBase = nullptr;
		PEPROCESS pSystem = nullptr;
		SIZE_T nViewSize = NULL;
		KAPC_STATE apcState{ 0 };
		CLIENT_ID clientId{ ULongToHandle(4u), nullptr };
		UNICODE_STRING objectPath = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");
		OBJECT_ATTRIBUTES objectAttributes{ 0 };
		InitializeObjectAttributes(
			&objectAttributes,
			&objectPath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			nullptr,
			nullptr);

		//
		// Get user space address for ntdll.dll from KnownDlls section
		//
		ntstatus = ::ZwOpenSection(&hSection, SECTION_MAP_READ, &objectAttributes);

		if (!NT_SUCCESS(ntstatus))
		{
			hSection = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to ZwOpenSection() (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		//
		// Get routine address by PE analyzing from mapped \KnownDlls\ntdll.dll in System process
		//
		::memset(&objectAttributes, 0, sizeof(OBJECT_ATTRIBUTES));
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
		objectAttributes.Attributes = OBJ_KERNEL_HANDLE;

		ntstatus = ::ZwOpenProcess(&hSystem, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);

		if (!NT_SUCCESS(ntstatus))
		{
			hSystem = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to ZwOpenProcess() for System (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Got System process handle 0x%p.\n", hSystem));
		}

		ntstatus = ::ZwMapViewOfSection(
			hSection,
			hSystem,
			&pSectionBase,
			0u,
			0u,
			nullptr,
			&nViewSize,
			ViewUnmap,
			NULL,
			PAGE_READWRITE);

		if (!NT_SUCCESS(ntstatus) && (ntstatus != STATUS_IMAGE_NOT_AT_BASE))
		{
			KdPrint((DRIVER_PREFIX "Failed to ZwMapViewOfSection() for System (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "ntdll.dll section is mapped at 0x%p in System.\n", pSectionBase));
		}

		::PsLookupProcessByProcessId(ULongToHandle(4u), &pSystem);
		::KeStackAttachProcess(pSystem, &apcState);

		__try
		{
			if (*(USHORT*)pSectionBase == 0x5A4D)
			{
				auto e_lfanew = ((PIMAGE_DOS_HEADER)pSectionBase)->e_lfanew;
				auto pImageNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pSectionBase + e_lfanew);
				auto nExportDirectoryOffset = pImageNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
				auto pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pSectionBase + nExportDirectoryOffset);
				auto pOrdinals = (USHORT*)((ULONG_PTR)pSectionBase + pExportDirectory->AddressOfNameOrdinals);
				auto pNames = (ULONG*)((ULONG_PTR)pSectionBase + pExportDirectory->AddressOfNames);
				auto pFunctions = (ULONG*)((ULONG_PTR)pSectionBase + pExportDirectory->AddressOfFunctions);
				auto nEntries = pExportDirectory->NumberOfNames;
				auto nStrLen = ::strlen(syscallName);

				for (auto idx = 0u; idx < nEntries; idx++)
				{
					auto functionName = (PCHAR)((ULONG_PTR)pSectionBase + pNames[idx]);

					if (::strncmp(functionName, syscallName, nStrLen) == 0)
					{
						auto pRoutine = (PUCHAR)((ULONG_PTR)pSectionBase + pFunctions[pOrdinals[idx]]);

						for (auto offset = 0u; offset < 0x20; offset++)
						{
							if (*(USHORT*)&pRoutine[offset] == 0x050F) // syscall instruction
								break;

							if (pRoutine[offset] == 0xB8) // mov eax, ??
							{
								nSyscallNumber = *(LONG*)&pRoutine[offset + 1];
								break;
							}
						}

						break;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint((DRIVER_PREFIX "Access violation in user space.\n"));
		}

		::KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(pSystem);

		ntstatus = ::ZwUnmapViewOfSection(hSystem, pSectionBase);

		if (!NT_SUCCESS(ntstatus))
			KdPrint((DRIVER_PREFIX "Failed to ZwUnmapViewOfSection() for System (NTSTATUS = 0x%08X).\n", ntstatus));
		else
			KdPrint((DRIVER_PREFIX "ntdll.dll section is unmapped from System.\n"));
	} while (false);

	if (hSystem != nullptr)
		::ZwClose(hSystem);

	if (hSection != nullptr)
		::ZwClose(hSection);

	KdPrint((DRIVER_PREFIX "Syscall number of %s : %02X.\n", syscallName, nSyscallNumber));

	return nSyscallNumber;
}


PVOID GetZwCreateTokenBase()
{
	PVOID pZwCreateToken = nullptr;
	PVOID pKernel = GetKernelBase();
	LONG nSyscallNumber = GetSystcallNumber(const_cast<PCHAR>("ZwCreateToken"));

	if ((pKernel == nullptr) || (nSyscallNumber == -1L))
		return nullptr;

	PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeEntry = nullptr;
	auto e_lfanew = ((PIMAGE_DOS_HEADER)pKernel)->e_lfanew;
	auto pImageNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pKernel + e_lfanew);
	auto nSections = pImageNtHeader->FileHeader.NumberOfSections;
	auto pSection = (PIMAGE_SECTION_HEADER)(
		(ULONG_PTR)pImageNtHeader +
		FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
		pImageNtHeader->FileHeader.SizeOfOptionalHeader);
	ULONG nCount = 0u;

	for (auto idx = 0; idx < nSections; idx++)
	{
		if (::_strnicmp(pSection[idx].Name, const_cast<PCHAR>(".pdata"), 6) == 0)
		{
			pRuntimeEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((ULONG_PTR)pKernel + pSection[idx].VirtualAddress);
			break;
		}
	}

	while ((pRuntimeEntry != nullptr) && (pRuntimeEntry[nCount].BeginAddress != NULL))
	{
		auto pFunctionBase = (PUCHAR)((ULONG_PTR)pKernel + pRuntimeEntry[nCount].BeginAddress);
		auto nFunctionSize = pRuntimeEntry[nCount].EndAddress - pRuntimeEntry[nCount].BeginAddress;

		for (auto idx = 0; idx < (nFunctionSize - 5); idx++)
		{
			if ((pFunctionBase[idx] != 0xB8) || (pFunctionBase[idx + 5] != 0xE9)) // mov eax, ??; jmp ??
				continue;

			if (*(LONG*)&pFunctionBase[idx + 1] == nSyscallNumber)
			{
				pZwCreateToken = (PVOID)pFunctionBase;
				break;
			}
		}

		if (pZwCreateToken != nullptr)
			break;

		nCount++;
	}

	KdPrint((DRIVER_PREFIX "ZwCreateToken is at 0x%p\n", (PVOID)pZwCreateToken));

	return pZwCreateToken;
}


NTSTATUS CreateElavatedToken(_Out_ PHANDLE pTokenHandle)
{
	NTSTATUS ntstatus = STATUS_INSUFFICIENT_RESOURCES;
	// Everyone : S-1-1-0
	ULONG everyoneSid[] = { 0x00000101, 0x01000000, 0x00000000 };
	// NT AUTHORITY\Authenticated Users : S-1-5-11
	ULONG authUsersSid[] = { 0x00000101, 0x05000000, 0x0000000B };
	// NT AUTHORITY\SYSTEM : S-1-5-18
	ULONG systemSid[] = { 0x00000101, 0x05000000, 0x00000012 };
	// Mandatory Label\System Mandatory Level : S-1-16-16384
	ULONG systemLevelSid[] = { 0x00000101, 0x10000000, 0x00004000 };
	// BUILTIN\Administrators : S-1-5-32-544
	ULONG adminSid[] = { 0x00000201, 0x05000000, 0x00000020, 0x00000220 };
	// NT SERVICE\TrustedInstaller : S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
	ULONG trustedInstallerSid[] = { 0x00000601, 0x05000000, 0x00000050, 0x38FB89B5, 0xCBC28419, 0x6D236C5C, 0x6E770057, 0x876402C0 };
	// NT SERVICE\WinDefend : S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736
	ULONG windefendSid[] = { 0x00000601, 0x05000000, 0x00000050, 0x720855BF, 0xD028E03B, 0xF84B7989, 0x7C6E8991, 0xF4EC2540 };
	LUID authLuid = SYSTEM_LUID;
	LARGE_INTEGER expirationTime{ 0xFFFFFFFFu, -1L };
	TOKEN_USER tokenUser{ { &systemSid, 0 } };
	PTOKEN_GROUPS pTokenGroups = nullptr;
	PTOKEN_PRIVILEGES pTokenPrivileges = nullptr;
	TOKEN_OWNER tokenOwner{ &systemSid };
	TOKEN_PRIMARY_GROUP tokenPrimaryGroup{ &systemSid };
	TOKEN_DEFAULT_DACL tokenDefaultDacl{ nullptr };
	PACL pDefaultDacl = nullptr;
	PACCESS_ALLOWED_ACE pAce = nullptr;
	USHORT nAceSize = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + (sizeof(ULONG) * 4);
	TOKEN_SOURCE tokenSource{ { '*', 'S', 'Y', 'S', 'T', 'E', 'M', '*' }, { 0, 0 } };
	OBJECT_ATTRIBUTES objectAttributes{ };
	objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	pTokenGroups = (PTOKEN_GROUPS)::ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		FIELD_OFFSET(TOKEN_GROUPS, Groups) + (sizeof(SID_AND_ATTRIBUTES) * 7),
		(ULONG)DRIVER_TAG);

	pTokenPrivileges = (PTOKEN_PRIVILEGES)::ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) + (sizeof(LUID_AND_ATTRIBUTES) * 35),
		(ULONG)DRIVER_TAG);

	pDefaultDacl = (PACL)::ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(ACL) + (SIZE_T)(nAceSize * 2),
		(ULONG)DRIVER_TAG);

	if ((pTokenGroups == nullptr) || (pTokenPrivileges == nullptr) || (pDefaultDacl == nullptr))
	{
		KdPrint((DRIVER_PREFIX "Failed to allocate non-paged pool.\n"));
	}
	else
	{
		// 
		// Build TOKEN_GROUPS
		//
		pTokenGroups->GroupCount = 7;
		// BUILTIN\Administrators
		pTokenGroups->Groups[0].Sid = &adminSid;
		pTokenGroups->Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER;
		// NT AUTHORITY\Authenticated Users
		pTokenGroups->Groups[1].Sid = &authUsersSid;
		pTokenGroups->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		// Everyone
		pTokenGroups->Groups[2].Sid = &everyoneSid;
		pTokenGroups->Groups[2].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		// NT SERVICE\TrustedInstaller
		pTokenGroups->Groups[3].Sid = &trustedInstallerSid;
		pTokenGroups->Groups[3].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		// NT SERVICE\WinDefend
		pTokenGroups->Groups[4].Sid = &windefendSid;
		pTokenGroups->Groups[4].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		// NT AUTHORITY\SYSTEM
		pTokenGroups->Groups[5].Sid = &systemSid;
		pTokenGroups->Groups[5].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		// Mandatory Label\System Mandatory Level
		pTokenGroups->Groups[6].Sid = &systemLevelSid;
		pTokenGroups->Groups[6].Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;

		// 
		// Build TOKEN_PRIVILEGES
		//
		pTokenPrivileges->PrivilegeCount = 35;

		for (auto count = 0; count < 35; count++)
		{
			pTokenPrivileges->Privileges[count].Luid.LowPart = count + 2;
			pTokenPrivileges->Privileges[count].Luid.HighPart = 0;
			pTokenPrivileges->Privileges[count].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;
		}

		//
		// Build TOKEN_DEFAULT_DACL
		//
		pDefaultDacl->AclRevision = ACL_REVISION2;
		pDefaultDacl->AclSize = (USHORT)sizeof(ACL) + (2 * nAceSize);
		pDefaultDacl->AceCount = 2;
		// NT AUTHORITY\SYSTEM : GenericAll
		pAce = (PACCESS_ALLOWED_ACE)((ULONG_PTR)pDefaultDacl + sizeof(ACL));
		pAce->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
		pAce->Header.AceFlags = NULL;
		pAce->Header.AceSize = nAceSize;
		pAce->Mask = GENERIC_ALL;
		::memcpy(&pAce->SidStart, &systemSid, sizeof(systemSid));
		// BUILTIN\Administrators : ReadControl, GenericExecute, GenericRead
		pAce = (PACCESS_ALLOWED_ACE)((ULONG_PTR)pAce + nAceSize);
		pAce->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
		pAce->Header.AceFlags = NULL;
		pAce->Header.AceSize = nAceSize;
		pAce->Mask = READ_CONTROL | GENERIC_EXECUTE | GENERIC_READ;
		::memcpy(&pAce->SidStart, &adminSid, sizeof(adminSid));
		tokenDefaultDacl.DefaultDacl = pDefaultDacl;

		//
		// Create full privileged token
		//
		ntstatus = ZwCreateToken(
			pTokenHandle,
			TOKEN_ALL_ACCESS,
			&objectAttributes,
			TokenPrimary,
			&authLuid,
			&expirationTime,
			&tokenUser,
			pTokenGroups,
			pTokenPrivileges,
			&tokenOwner,
			&tokenPrimaryGroup,
			&tokenDefaultDacl,
			&tokenSource);

		if (!NT_SUCCESS(ntstatus))
		{
			*pTokenHandle = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to ZwCreateToken() API (NTSTATUS = 0x%08X).\n", ntstatus));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "ZwCreateToken() API is successful (Handle = 0x%X).\n", HandleToULong(*pTokenHandle)));
		}
	}
	
	if (pDefaultDacl != nullptr)
		::ExFreePoolWithTag(pDefaultDacl, (ULONG)DRIVER_TAG);

	if (pTokenPrivileges != nullptr)
		::ExFreePoolWithTag(pTokenPrivileges, (ULONG)DRIVER_TAG);

	if (pTokenGroups != nullptr)
		::ExFreePoolWithTag(pTokenGroups, (ULONG)DRIVER_TAG);

	return ntstatus;
}


LONG GetCurrentTokenSessionId()
{
	LONG sessionId = -1;
	HANDLE hToken = nullptr;
	NTSTATUS ntstatus = ::ZwOpenProcessTokenEx(
		(HANDLE)-1,
		TOKEN_ALL_ACCESS,
		0u,
		&hToken);

	if (NT_SUCCESS(ntstatus))
	{
		ULONG nReturnedLength = 0u;
		ntstatus = ::ZwQueryInformationToken(
			hToken,
			TokenSessionId,
			&sessionId,
			sizeof(LONG),
			&nReturnedLength);
		::ZwClose(hToken);

		if (!NT_SUCCESS(ntstatus))
			sessionId = -1;
	}

	return sessionId;
}