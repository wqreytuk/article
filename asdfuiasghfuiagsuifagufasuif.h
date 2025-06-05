
typedef GUID CLFS_LOG_ID;
typedef  UCHAR CLFS_CLIENT_ID;
typedef UCHAR CLFS_LOG_STATE, *PCLFS_LOG_STATE;
typedef struct _CLFS_METADATA_RECORD_HEADER {
	ULONGLONG ullDumpCount;
}CLFS_METADATA_RECORD_HEADER, *PCLFS_METADATA_RECORD_HEADER;
typedef struct _CLFS_BASE_RECORD_HEADER {
	CLFS_METADATA_RECORD_HEADER hdrBaseRecord;
	CLFS_LOG_ID cidLog;

	ULONGLONG rgClientSymTbl[0xb];
	ULONGLONG rgContainerSyMTbI[0xb];
	ULONGLONG rgSecuritySymTbI[0xb];

	ULONG cNextcontainer;
	CLFS_CLIENT_ID cNextclient;

	ULONG cFreeContainers;
	ULONG cActiveContainers;

	ULONG cbFreecontainers;
	ULONG cbBusyContainers;

	ULONG rgClientS[0x7c];
	ULONG rgContainerS[0x400];

	ULONG cbSymbolZone;
	ULONG cbsector;
	USHORT bUnused;
	CLFS_LOG_STATE eLogState;

	UCHAR cUsn;
	UCHAR cClients;
}CLFS_BASE_RECORD_HEADER, *PCLFS_BASE_RECORD_HEADER;