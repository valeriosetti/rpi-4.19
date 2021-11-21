#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/kdev_t.h>
#include <linux/vmalloc.h>
#include <linux/sysfs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <uapi/linux/stat.h>

#include "fake_mass_storage.h"

#undef pr_fmt
#define pr_fmt(fmt)		"fake_mass_storage: "fmt

#define N_SECTORS			(2*1024*100) // 512*2*1024*100 = 100 MB

#define MP3_ENCODE_RATE			192000  // kbits/s - it's the supposed encoding rate
#define MP3_PLAYBACK_BUFFER		4  // seconds
#define VMALLOC_SIZE			(MP3_ENCODE_RATE/8*MP3_PLAYBACK_BUFFER)  // bytes

struct {
	uint32_t read_idx;
	uint32_t write_idx;
	size_t valid_bytes;
	uint8_t* data;
	struct mutex lock_mutex;
	volatile uint8_t fill_buffer;
} data_buffer;

#define MAX_DATA_READY_TIMEOUT		10	// ms

/*
 * read 1 sector of FAT data
 */
static size_t read_fat_data(unsigned long sector, char *buf)
{
	int index = 0;	// index of the uint32 element in the sector
	int elements_per_fat_sector = FBD_SECTOR_SIZE/sizeof(uint32_t);	// number or entries in each
																	// sector of the FAT table
	int cluster_index; // the cluster to be referenced in FAT table
	uint32_t* buf32 = (uint32_t*)buf;
	
	// FAT1 and FAT2 are identical, so same data should be returned
	if (sector >= FAT2_START_LBA) {
		sector = sector - FAT2_START_LBA;
	} else {
		sector = sector - FAT1_START_LBA;
	}
	
	cluster_index = sector * elements_per_fat_sector + 1;
	
	// the 1st sector of the FAT table has the first 2 elemements which are predefined
	// and the 3rd one which is for the root directory (also predefined)
	if (sector == 0x0) {
		buf32[0] = cpu_to_le32(END_OF_FILE); 
		buf32[1] = cpu_to_le32(END_OF_FILE); 
		buf32[2] = cpu_to_le32(END_OF_FILE);
		index = 3;
		cluster_index += 3;  // cluster index in FAT always refers to the next cluster
	}
	
	while (index < elements_per_fat_sector) {
		if (cluster_index < VIRTUAL_FILE_LAST_CLUSTER) {
			buf32[index] = cpu_to_le32(cluster_index);
		} else if (cluster_index == VIRTUAL_FILE_LAST_CLUSTER) {
			buf32[index] = cpu_to_le32(3);
		} else {
			buf32[index] = cpu_to_le32(0);
		}
		cluster_index++;
		index++;
	}
	
	return FBD_SECTOR_SIZE;
}

static size_t read_sector_from_internal_buffer(char *buf)
{
	size_t tmp_len;
	size_t remaining_len = FBD_SECTOR_SIZE;
	//unsigned long stop_jiffies = jiffies + msecs_to_jiffies(MAX_DATA_READY_TIMEOUT);
	
	//pr_info("%s\n", __func__);
	
	data_buffer.fill_buffer = true;
	
	// wait until there's enough data to transfer in the buffer
	//while (data_buffer.valid_bytes < remaining_len) {
	//	//pr_info("not enough data in the buffer. Wait\n");
	//	mdelay(5);
	//	
	//	if (time_is_before_eq_jiffies(stop_jiffies)) {
	//		//pr_warn("Warning: timeout reached without incoming data. Filling with zeros\n");
	//		memset(buf, 0, remaining_len);
	//		return remaining_len;
	//	} 
	//}
	if (data_buffer.valid_bytes < remaining_len) {
		memset(buf, 0, remaining_len);
		return remaining_len;
	}
	
	mutex_lock(&(data_buffer.lock_mutex));
	while (remaining_len > 0) {
		// get the correct amount of data to be copied
		tmp_len = min(remaining_len, (size_t)(VMALLOC_SIZE - data_buffer.read_idx));
		
		memcpy(buf, &data_buffer.data[data_buffer.read_idx], tmp_len);
		data_buffer.valid_bytes -= tmp_len;
		data_buffer.read_idx += tmp_len;
		if (data_buffer.read_idx >= VMALLOC_SIZE) {
			data_buffer.read_idx = 0;
		}
		buf += tmp_len;
		remaining_len -= tmp_len;
	}
	
	//pr_info("%s: buffer is %d/%d full - write_idx=%d - read_idx=%d", __func__, data_buffer.valid_bytes, VMALLOC_SIZE, data_buffer.write_idx, data_buffer.read_idx);
	
	mutex_unlock(&(data_buffer.lock_mutex));
	
	return FBD_SECTOR_SIZE;
}

ssize_t fms_read(unsigned long sector, unsigned long nsect, char *buffer)
{
	ssize_t read_data_size = 0;
	
	if (sector >= N_SECTORS) {
		pr_err("Error: trying to access to an invalid sector (%ld)\n", sector);
		return -EIO;
	}
	
	pr_info("Reading %lu sectors starting at 0x%lx\n", nsect, sector); 
	while (nsect > 0) {
		#ifdef SIMULATE_ENTIRE_DISK
		if (sector == MBR_LBA) {
			pr_info("Return MBR data\n");
			memcpy(buffer, mbr, FBD_SECTOR_SIZE);
		} else 
		#endif
		if (sector == PARTITION_INFO_1_LBA) {
			pr_info("Return partition info 1 data\n");
			memcpy(buffer, partition_info_1, FBD_SECTOR_SIZE);
		} else if (sector == PARTITION_INFO_2_LBA) {
			pr_info("Return partition info 2 data\n");
			memcpy(buffer, partition_info_2, FBD_SECTOR_SIZE);
		} else if ((sector >= FAT1_START_LBA) && (sector < FAT2_START_LBA)) {
			pr_info("Return FAT1 data\n");
			read_fat_data(sector, buffer);
		} else if ((sector >= FAT2_START_LBA) && (sector < CLUSTER2_START_LBA)) {
			pr_info("Return FAT2 data\n");
			read_fat_data(sector, buffer);
		} else if ((sector >= CLUSTER2_START_LBA) && (sector < CLUSTER3_START_LBA)) {
			pr_info("Return cluster2 data\n");
			memcpy(buffer, cluster_2, FBD_SECTOR_SIZE);
		} else if ((sector >= CLUSTER3_START_LBA) && (sector < VIRTUAL_FILE_LAST_CLUSTER_LBA)) {
			pr_info("Return file content data\n");
			read_sector_from_internal_buffer(buffer);
		} else {
			pr_info("sector 0x%lx not known. Filling with 0\n", sector);
			memset(buffer, 0, FBD_SECTOR_SIZE);
		}
		buffer += FBD_SECTOR_SIZE;
		sector++;
		nsect--;
		read_data_size += FBD_SECTOR_SIZE;
	}
		
	return read_data_size;
}

ssize_t fms_write(const char *buf, size_t len, loff_t *off)
{
	size_t tmp_len;
	size_t remaining_len = len;
	unsigned long copied_data;
	
	pr_info("%s: writing %d bytes\n", __func__, len);
	
	if (!data_buffer.fill_buffer) {
		pr_info("%s: no one is reading the file. Skip buffer filling\n", __func__);
		return len;
	}
	
	mutex_lock(&(data_buffer.lock_mutex));
	
	while (remaining_len > 0) {
		tmp_len = min((size_t)(VMALLOC_SIZE - data_buffer.write_idx), remaining_len);
		
		copied_data = copy_from_user(&(data_buffer.data[data_buffer.write_idx]), buf, tmp_len);
		if (copied_data != tmp_len) {
			pr_warn("Warning: requested %d bytes, but copied %lu", tmp_len, copied_data);
		}
		
		data_buffer.write_idx += tmp_len;
		if (data_buffer.write_idx >= VMALLOC_SIZE) {
			data_buffer.write_idx = 0;
		}
		
		remaining_len -= tmp_len;
	}
	
	data_buffer.valid_bytes += len;
	// (1) there should be at max VMALLOC_SIZE valid bytes in the buffer
	// (2) in case of full buffer, the read_idx must be moved forward to the last write_idx
	if (data_buffer.valid_bytes >= VMALLOC_SIZE) {
		data_buffer.valid_bytes = VMALLOC_SIZE;
		data_buffer.read_idx = data_buffer.write_idx;
		data_buffer.fill_buffer = false;
	}
	
	mutex_unlock(&(data_buffer.lock_mutex));
	
	pr_info("%s: buffer is %d/%d full - write_idx=%d - read_idx=%d", __func__, data_buffer.valid_bytes, VMALLOC_SIZE, data_buffer.write_idx, data_buffer.read_idx);
	
	return len;
}

int fms_init(void)
{
	// initialize the internal buffer
	data_buffer.write_idx = 0;
	data_buffer.read_idx = 0;
	data_buffer.valid_bytes = 0;
	data_buffer.fill_buffer = false;
	data_buffer.data = vmalloc(VMALLOC_SIZE);
	if (data_buffer.data == NULL) {
		pr_err("vmalloc() failed\n");
		goto out_unregister;
	}
	
	pr_info("Allocated internal buffer of %d bytes\n", VMALLOC_SIZE);
	
	return 0;

out_unregister:
	pr_err("Error: init failed\n");
	return -ENOMEM;
}

void fms_exit(void)
{
	if (data_buffer.data != NULL) {
		vfree(data_buffer.data);
	}
	
	pr_info("exit\n");
}
