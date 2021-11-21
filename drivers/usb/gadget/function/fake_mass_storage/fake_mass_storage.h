#include "lookup_table.h"
#include "linux/stddef.h"

#define FBD_SECTOR_SIZE		512 // fixed

// uncomment the following define in order to include also MBR
#define SIMULATE_ENTIRE_DISK

#ifdef SIMULATE_ENTIRE_DISK
	//#pragma message("simulating entire disk")
	#define SECTORS_SHIFT	0x800
#else
	//#pragma message("simulate partition only")
	#define SECTORS_SHIFT	0x0
#endif

#define SECTORS_PER_CLUSTER 	1
#define SECTORS_PER_FAT			0x618
#define END_OF_FILE				0x0FFFFFF8

#define MBR_LBA			0x0
// MBR uses lookup data

#define PARTITION_INFO_1_LBA		(SECTORS_SHIFT + 0x0)
#define PARTITION_INFO_2_LBA		(SECTORS_SHIFT + 0x1)
// partition info uses lookup data

#define FAT1_START_LBA		(SECTORS_SHIFT + 0x20)
#define FAT2_START_LBA		(SECTORS_SHIFT + 0x20 + SECTORS_PER_FAT)

// cluster 2 is for the root dir 
#define CLUSTER2_START_LBA		(FAT2_START_LBA + SECTORS_PER_FAT)

// cluster 3 is the first which contains actual data
#define CLUSTER3_START_LBA			(CLUSTER2_START_LBA + SECTORS_PER_CLUSTER)

#define VIRTUAL_FILE_SIZE		52428800  // bytes
#define VIRTUAL_FILE_CLUSTERS	((VIRTUAL_FILE_SIZE/FBD_SECTOR_SIZE)/SECTORS_PER_CLUSTER)
#define VIRTUAL_FILE_FIRST_CLUSTER_LBA		CLUSTER3_START_LBA
#define VIRTUAL_FILE_FIRST_CLUSTER			3
#define VIRTUAL_FILE_LAST_CLUSTER_LBA		(VIRTUAL_FILE_FIRST_CLUSTER_LBA + VIRTUAL_FILE_CLUSTERS)
#define VIRTUAL_FILE_LAST_CLUSTER			(3 + VIRTUAL_FILE_CLUSTERS)


int fms_init(void);
void fms_exit(void);
ssize_t fms_read(unsigned long sector, unsigned long nsect, char *buffer);
ssize_t fms_write(const char *buf, size_t len, loff_t *off);
