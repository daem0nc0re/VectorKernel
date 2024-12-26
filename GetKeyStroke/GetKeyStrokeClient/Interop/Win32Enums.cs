using System;

namespace GetKeyStrokeClient.Interop
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
        NO_ACCESS = 0x00000000,

        // For Events
        EVENT_QUERY_STATE = 0x00000001,
        EVENT_MODIFY_STATE = 0x00000002,
        EVENT_ALL_ACCESS = 0x001F0003,

        // For Files
        FILE_ANY_ACCESS = 0x00000000,
        FILE_READ_ACCESS = 0x00000001,
        FILE_WRITE_ACCESS = 0x00000002,
        FILE_READ_DATA = 0x00000001,
        FILE_LIST_DIRECTORY = 0x00000001,
        FILE_WRITE_DATA = 0x00000002,
        FILE_ADD_FILE = 0x00000002,
        FILE_APPEND_DATA = 0x00000004,
        FILE_ADD_SUBDIRECTORY = 0x00000004,
        FILE_CREATE_PIPE_INSTANCE = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_EXECUTE = 0x00000020,
        FILE_TRAVERSE = 0x00000020,
        FILE_DELETE_CHILD = 0x00000040,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        FILE_ALL_ACCESS = 0x001F01FF,
        FILE_GENERIC_READ = 0x00100089,
        FILE_GENERIC_WRITE = 0x00100116,
        FILE_GENERIC_EXECUTE = 0x001000A0,

        // Standard and Generic Rights
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000,
    }

    internal enum BOOLEAN : byte
    {
        FALSE = 0,
        TRUE
    }

    internal enum CTRL_TYPES
    {
        C_EVENT = 0,
        BREAK_EVENT = 1,
        CLOSE_EVENT = 2,
        LOGOFF_EVENT = 5,
        SHUTDOWN_EVENT = 6
    }

    internal enum DAY_OF_WEEK : short
    {
        Sun,
        Mon,
        Tue,
        Wed,
        Thu,
        Fri,
        Sat
    }

    internal enum EVENT_TYPE
    {
        NotificationEvent,
        SynchronizationEvent
    }

    [Flags]
    internal enum FILE_ATTRIBUTE_FLAGS : uint
    {
        ReadOnly = 0x00000001,
        Hidden = 0x00000002,
        System = 0x00000004,
        Directory = 0x00000010,
        Archive = 0x00000020,
        Device = 0x00000040,
        Normal = 0x00000080,
        Temporary = 0x00000100,
        SparseFile = 0x00000200,
        ReparsePoint = 0x00000400,
        Compressed = 0x00000800,
        Offline = 0x00001000,
        NotContentIndexed = 0x00002000,
        Encrypted = 0x00004000,
        IntegrityStream = 0x00008000,
        Virtual = 0x00010000,
        NoScrubData = 0x00020000,
        Ea = 0x00040000,
        Pinned = 0x00080000,
        Unpinned = 0x00100000,
        RecallOnOpen = 0x00040000,
        RecallOnDataAccess = 0x00400000
    }

    [Flags]
    internal enum FILE_CREATE_OPTIONS : uint
    {
        NONE = 0x00000000,
        DIRECTORY_FILE = 0x00000001,
        WRITE_THROUGH = 0x00000002,
        SEQUENTIAL_ONLY = 0x00000004,
        NO_INTERMEDIATE_BUFFERING = 0x00000008,
        SYNCHRONOUS_IO_ALERT = 0x00000010,
        SYNCHRONOUS_IO_NONALERT = 0x00000020,
        NON_DIRECTORY_FILE = 0x00000040,
        CREATE_TREE_CONNECTION = 0x00000080,
        COMPLETE_IF_OPLOCKED = 0x00000100,
        NO_EA_KNOWLEDGE = 0x00000200,
        OPEN_FOR_RECOVERY = 0x00000400,
        RANDOM_ACCESS = 0x00000800,
        DELETE_ON_CLOSE = 0x00001000,
        OPEN_BY_FILE_ID = 0x00002000,
        OPEN_FOR_BACKUP_INTENT = 0x00004000,
        NO_COMPRESSION = 0x00008000,
        OPEN_REQUIRING_OPLOCK = 0x00010000,
        DISALLOW_EXCLUSIVE = 0x00020000,
        SESSION_AWARE = 0x00040000,
        RESERVE_OPFILTER = 0x00100000,
        OPEN_REPARSE_POINT = 0x00200000,
        OPEN_NO_RECALL = 0x00400000,
        OPEN_FOR_FREE_SPACE_QUERY = 0x00800000,
        COPY_STRUCTURED_STORAGE = 0x00000041,
        STRUCTURED_STORAGE = 0x00000441
    }

    internal enum FILE_CREATE_DISPOSITION : uint
    {
        SUPERSEDE = 0,
        OPEN = 1,
        CREATE = 2,
        OPEN_IF = 3,
        OVERWRITE = 4,
        OVERWRITE_IF = 5
    }

    internal enum FILE_INFORMATION_CLASS
    {
        FileDirectoryInformation = 1, // q: FILE_DIRECTORY_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
        FileFullDirectoryInformation, // q: FILE_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
        FileBothDirectoryInformation, // q: FILE_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
        FileBasicInformation, // q; s: FILE_BASIC_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
        FileStandardInformation, // q: FILE_STANDARD_INFORMATION, FILE_STANDARD_INFORMATION_EX
        FileInternalInformation, // q: FILE_INTERNAL_INFORMATION
        FileEaInformation, // q: FILE_EA_INFORMATION
        FileAccessInformation, // q: FILE_ACCESS_INFORMATION
        FileNameInformation, // q: FILE_NAME_INFORMATION
        FileRenameInformation, // s: FILE_RENAME_INFORMATION (requires DELETE) // 10
        FileLinkInformation, // s: FILE_LINK_INFORMATION
        FileNamesInformation, // q: FILE_NAMES_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
        FileDispositionInformation, // s: FILE_DISPOSITION_INFORMATION (requires DELETE)
        FilePositionInformation, // q; s: FILE_POSITION_INFORMATION
        FileFullEaInformation, // FILE_FULL_EA_INFORMATION
        FileModeInformation, // q; s: FILE_MODE_INFORMATION
        FileAlignmentInformation, // q: FILE_ALIGNMENT_INFORMATION
        FileAllInformation, // q: FILE_ALL_INFORMATION (requires FILE_READ_ATTRIBUTES)
        FileAllocationInformation, // s: FILE_ALLOCATION_INFORMATION (requires FILE_WRITE_DATA)
        FileEndOfFileInformation, // s: FILE_END_OF_FILE_INFORMATION (requires FILE_WRITE_DATA) // 20
        FileAlternateNameInformation, // q: FILE_NAME_INFORMATION
        FileStreamInformation, // q: FILE_STREAM_INFORMATION
        FilePipeInformation, // q; s: FILE_PIPE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
        FilePipeLocalInformation, // q: FILE_PIPE_LOCAL_INFORMATION (requires FILE_READ_ATTRIBUTES)
        FilePipeRemoteInformation, // q; s: FILE_PIPE_REMOTE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
        FileMailslotQueryInformation, // q: FILE_MAILSLOT_QUERY_INFORMATION
        FileMailslotSetInformation, // s: FILE_MAILSLOT_SET_INFORMATION
        FileCompressionInformation, // q: FILE_COMPRESSION_INFORMATION
        FileObjectIdInformation, // q: FILE_OBJECTID_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
        FileCompletionInformation, // s: FILE_COMPLETION_INFORMATION // 30
        FileMoveClusterInformation, // s: FILE_MOVE_CLUSTER_INFORMATION (requires FILE_WRITE_DATA)
        FileQuotaInformation, // q: FILE_QUOTA_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
        FileReparsePointInformation, // q: FILE_REPARSE_POINT_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
        FileNetworkOpenInformation, // q: FILE_NETWORK_OPEN_INFORMATION (requires FILE_READ_ATTRIBUTES)
        FileAttributeTagInformation, // q: FILE_ATTRIBUTE_TAG_INFORMATION (requires FILE_READ_ATTRIBUTES)
        FileTrackingInformation, // s: FILE_TRACKING_INFORMATION (requires FILE_WRITE_DATA)
        FileIdBothDirectoryInformation, // q: FILE_ID_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
        FileIdFullDirectoryInformation, // q: FILE_ID_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
        FileValidDataLengthInformation, // s: FILE_VALID_DATA_LENGTH_INFORMATION (requires FILE_WRITE_DATA and/or SeManageVolumePrivilege)
        FileShortNameInformation, // s: FILE_NAME_INFORMATION (requires DELETE) // 40
        FileIoCompletionNotificationInformation, // q; s: FILE_IO_COMPLETION_NOTIFICATION_INFORMATION (q: requires FILE_READ_ATTRIBUTES) // since VISTA
        FileIoStatusBlockRangeInformation, // s: FILE_IOSTATUSBLOCK_RANGE_INFORMATION (requires SeLockMemoryPrivilege)
        FileIoPriorityHintInformation, // q; s: FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX (q: requires FILE_READ_DATA)
        FileSfioReserveInformation, // q; s: FILE_SFIO_RESERVE_INFORMATION (q: requires FILE_READ_DATA)
        FileSfioVolumeInformation, // q: FILE_SFIO_VOLUME_INFORMATION (requires FILE_READ_ATTRIBUTES)
        FileHardLinkInformation, // q: FILE_LINKS_INFORMATION
        FileProcessIdsUsingFileInformation, // q: FILE_PROCESS_IDS_USING_FILE_INFORMATION (requires FILE_READ_ATTRIBUTES)
        FileNormalizedNameInformation, // q: FILE_NAME_INFORMATION
        FileNetworkPhysicalNameInformation, // q: FILE_NETWORK_PHYSICAL_NAME_INFORMATION
        FileIdGlobalTxDirectoryInformation, // q: FILE_ID_GLOBAL_TX_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since WIN7 // 50
        FileIsRemoteDeviceInformation, // q: FILE_IS_REMOTE_DEVICE_INFORMATION (requires FILE_READ_ATTRIBUTES)
        FileUnusedInformation,
        FileNumaNodeInformation, // q: FILE_NUMA_NODE_INFORMATION
        FileStandardLinkInformation, // q: FILE_STANDARD_LINK_INFORMATION
        FileRemoteProtocolInformation, // q: FILE_REMOTE_PROTOCOL_INFORMATION
        FileRenameInformationBypassAccessCheck, // (kernel-mode only); s: FILE_RENAME_INFORMATION // since WIN8
        FileLinkInformationBypassAccessCheck, // (kernel-mode only); s: FILE_LINK_INFORMATION
        FileVolumeNameInformation, // q: FILE_VOLUME_NAME_INFORMATION
        FileIdInformation, // q: FILE_ID_INFORMATION
        FileIdExtdDirectoryInformation, // q: FILE_ID_EXTD_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // 60
        FileReplaceCompletionInformation, // s: FILE_COMPLETION_INFORMATION // since WINBLUE
        FileHardLinkFullIdInformation, // q: FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
        FileIdExtdBothDirectoryInformation, // q: FILE_ID_EXTD_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since THRESHOLD
        FileDispositionInformationEx, // s: FILE_DISPOSITION_INFO_EX (requires DELETE) // since REDSTONE
        FileRenameInformationEx, // s: FILE_RENAME_INFORMATION_EX
        FileRenameInformationExBypassAccessCheck, // (kernel-mode only); s: FILE_RENAME_INFORMATION_EX
        FileDesiredStorageClassInformation, // q; s: FILE_DESIRED_STORAGE_CLASS_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since REDSTONE2
        FileStatInformation, // q: FILE_STAT_INFORMATION (requires FILE_READ_ATTRIBUTES)
        FileMemoryPartitionInformation, // s: FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
        FileStatLxInformation, // q: FILE_STAT_LX_INFORMATION (requires FILE_READ_ATTRIBUTES and FILE_READ_EA) // since REDSTONE4 // 70
        FileCaseSensitiveInformation, // q; s: FILE_CASE_SENSITIVE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
        FileLinkInformationEx, // s: FILE_LINK_INFORMATION_EX // since REDSTONE5
        FileLinkInformationExBypassAccessCheck, // (kernel-mode only); s: FILE_LINK_INFORMATION_EX
        FileStorageReserveIdInformation, // q; s: FILE_STORAGE_RESERVE_ID_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
        FileCaseSensitiveInformationForceAccessCheck, // q; s: FILE_CASE_SENSITIVE_INFORMATION
        FileKnownFolderInformation, // q; s: FILE_KNOWN_FOLDER_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since WIN11
        FileStatBasicInformation, // since 23H2
        FileId64ExtdDirectoryInformation, // FILE_ID_64_EXTD_DIR_INFORMATION
        FileId64ExtdBothDirectoryInformation, // FILE_ID_64_EXTD_BOTH_DIR_INFORMATION
        FileIdAllExtdDirectoryInformation, // FILE_ID_ALL_EXTD_DIR_INFORMATION
        FileIdAllExtdBothDirectoryInformation, // FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION
        FileStreamReservationInformation, // FILE_STREAM_RESERVATION_INFORMATION // since 24H2
        FileMupProviderInfo, // MUP_PROVIDER_INFORMATION
        FileMaximumInformation
    }

    [Flags]
    internal enum FILE_NOTIFY_CHANGE_FLAGS : uint
    {
        FileName = 0x00000001,
        DirectoryName = 0x00000002,
        Name = 0x00000003,
        Attributes = 0x00000004,
        Size = 0x00000008,
        LastWrite = 0x00000010,
        LastAccess = 0x00000020,
        Creation = 0x00000040,
        Ea = 0x00000080,
        Security = 0x00000100,
        StreamName = 0x00000200,
        StreamSize = 0x00000400,
        StreamWrite = 0x00000800
    }

    [Flags]
    internal enum FILE_SHARE_ACCESS : uint
    {
        NONE = 0x00000000,
        READ = 0x00000001,
        WRITE = 0x00000002,
        DELETE = 0x00000004,
        VALID_FLAGS = 0x00000007
    }

    [Flags]
    internal enum KEY_ACTION_FLAGS : ushort
    {
        MAKE = 0x0000,
        BREAK = 0x0001,
        E0 = 0x0002,
        E1 = 0x0004,
        TERMSRV_SET_LED = 0x0008,
        TERMSRV_SHADOW = 0x0010,
        TERMSRV_VKPACKET = 0x0020,
        RIM_VKEY = 0x0040,
        FROM_KEYBOARD_OVERRIDER = 0x0080,
        UNICODE_SEQUENCE_ITEM = 0x0100,
        UNICODE_SEQUENCE_END = 0x0200
    }

    [Flags]
    internal enum OBJECT_ATTRIBUTES_FLAGS : uint
    {
        None = 0x00000000,
        ProtectClose = 0x00000001,
        Inherit = 0x00000002,
        AuditObjectClose = 0x00000004,
        NoEightsUpgrade = 0x00000008,
        Permanent = 0x00000010,
        Exclusive = 0x00000020,
        CaseInsensitive = 0x00000040,
        OpenIf = 0x00000080,
        OpenLink = 0x00000100,
        KernelHandle = 0x00000200,
        ForceAccessCheck = 0x00000400,
        IgnoreImpersonatedDevicemap = 0x00000800,
        DontReparse = 0x00001000,
        ValieAttributes = 0x00001FF2
    }
}
