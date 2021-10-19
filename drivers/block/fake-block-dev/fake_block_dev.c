#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/hdreg.h>	/* HDIO_GETGEO */
#include <linux/kdev_t.h>
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/sysfs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/miscdevice.h>
#include <uapi/linux/stat.h>

#include "fake_block_dev.h"

#undef pr_fmt
#define pr_fmt(fmt)		"fake_block_dev: "fmt

#define N_SECTORS			(2*1024*100) // 512*2*1024*100 = 100 MB

#define MP3_ENCODE_RATE			192000  // kbits/s - it's the supposed encoding rate
#define MP3_PLAYBACK_BUFFER		4  // seconds
#define VMALLOC_SIZE			(MP3_ENCODE_RATE/8*MP3_PLAYBACK_BUFFER)  // bytes

#if defined(DEBUG)
	#warning "Compiling with debug enabled"
#endif

struct fbd_dev {
	int size;                    /* Device size in sectors */
	short users;                 /* How many users */
	spinlock_t lock;             /* For mutual exclusion */
	struct request_queue *queue; /* The device request queue */
	struct gendisk *gd;          /* The gendisk structure */
};

static struct fbd_dev *device_ptr = NULL;
static int fake_block_dev_major = 0;

struct {
	uint32_t read_idx;
	uint32_t write_idx;
	size_t valid_bytes;
	uint8_t* data;
	struct mutex lock_mutex;
	volatile uint8_t fill_buffer;
} data_buffer;

static dev_t char_dev_id;
static struct class* char_dev_class = NULL;
static struct cdev* fbd_cdev = NULL;
static struct device* fbd_char_dev = NULL;
static uint8_t is_char_dev_open = false;

#define MAX_DATA_READY_TIMEOUT		1000	// ms
static size_t read_sector_from_internal_buffer(char *buf);

/*
 * read 1 sector of FAT data
 */
static int read_fat_data(unsigned long sector, char *buf)
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
	
	return 0;
}

static int fbd_transfer(struct fbd_dev *dev, unsigned long sector, unsigned long nsect, char *buffer, int write)
{
	if (sector >= N_SECTORS) {
		pr_err("Error: trying to access to an invalid sector (%ld)\n", sector);
		return -1;
	}
	if (write) {
		pr_warn("Warning: writing is not allowed on this device\n");
		return -1;
	} else {
		pr_debug("Reading %lu sectors starting at 0x%lx\n", nsect, sector); 
		while (nsect > 0) {
			#ifdef SIMULATE_ENTIRE_DISK
			if (sector == MBR_LBA) {
				pr_debug("Return MBR data\n");
				memcpy(buffer, mbr, FBD_SECTOR_SIZE);
			} else 
			#endif
			if (sector == PARTITION_INFO_1_LBA) {
				pr_debug("Return partition info 1 data\n");
				memcpy(buffer, partition_info_1, FBD_SECTOR_SIZE);
			} else if (sector == PARTITION_INFO_2_LBA) {
				pr_debug("Return partition info 2 data\n");
				memcpy(buffer, partition_info_2, FBD_SECTOR_SIZE);
			} else if ((sector >= FAT1_START_LBA) && (sector < FAT2_START_LBA)) {
				pr_debug("Return FAT1 data\n");
				read_fat_data(sector, buffer);
			} else if ((sector >= FAT2_START_LBA) && (sector < CLUSTER2_START_LBA)) {
				pr_debug("Return FAT2 data\n");
				read_fat_data(sector, buffer);
			} else if ((sector >= CLUSTER2_START_LBA) && (sector < CLUSTER3_START_LBA)) {
				pr_debug("Return cluster2 data\n");
				memcpy(buffer, cluster_2, FBD_SECTOR_SIZE);
			} else if ((sector >= CLUSTER3_START_LBA) && (sector < VIRTUAL_FILE_LAST_CLUSTER_LBA)) {
				pr_debug("Return file content data\n");
				read_sector_from_internal_buffer(buffer);
			} else {
				pr_debug("sector 0x%lx not known. Filling with 0\n", sector);
				memset(buffer, 0, FBD_SECTOR_SIZE);
			}
			buffer += FBD_SECTOR_SIZE;
			sector++;
			nsect--;
		}
	}
	return 0;
}

static int fbd_xfer_bio(struct fbd_dev *dev, struct bio *bio)
{
	struct bvec_iter bvec_iter_ptr;
	struct bio_vec bvec;
	sector_t sector = bio->bi_iter.bi_sector;
	int ret;

	bio_for_each_segment(bvec, bio, bvec_iter_ptr) {
		char *buffer = kmap_atomic(bvec.bv_page) + bvec.bv_offset;
		ret = fbd_transfer(dev, sector, bio_cur_bytes(bio) >> 9, buffer, bio_data_dir(bio) == WRITE);
		if (ret < 0) {
			return ret;
		}
		sector += bio_cur_bytes(bio) >> 9;
		kunmap_atomic(buffer);
	}
	return 0;
}

static blk_qc_t fbd_make_request(struct request_queue *q, struct bio *bio)
{
	struct fbd_dev *dev = q->queuedata;
	int status;

	status = fbd_xfer_bio(dev, bio);
	if (status < 0) {
		bio_io_error(bio);
	} else {
		bio_endio(bio);
	}
	
	return 0;
}

static int fbd_open(struct block_device *bdev, fmode_t mode)
{
	struct fbd_dev *dev = bdev->bd_disk->private_data;

	spin_lock(&dev->lock);
	dev->users++;
	spin_unlock(&dev->lock);
	pr_debug("open count: %d\n", dev->users);
	return 0;
}

static void fbd_release(struct gendisk *disk, fmode_t mode)
{
	struct fbd_dev *dev = disk->private_data;

	spin_lock(&dev->lock);
	dev->users--;
	spin_unlock(&dev->lock);
	pr_debug("open count: %d\n", dev->users);
}

int fbd_media_changed(struct gendisk *gd)
{
	pr_debug("%s\n", __func__);
	return 0;
}

int fbd_revalidate(struct gendisk *gd)
{
	pr_debug("%s\n", __func__);
	return 0;
}

int fbd_ioctl (struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	long size;
	struct hd_geometry geo;
	struct fbd_dev *dev = bdev->bd_disk->private_data;

	pr_debug("%s\n", __func__);
	switch(cmd) {
		case HDIO_GETGEO:
			size = dev->size*FBD_SECTOR_SIZE;
			geo.cylinders = (size & ~0x3f) >> 6;
			geo.heads = 4;
			geo.sectors = 16;
			geo.start = 4;
			if (copy_to_user((void __user *) arg, &geo, sizeof(geo)))
				return -EFAULT;
			return 0;
	}

	return -ENOTTY;
}

static struct block_device_operations fbd_ops = {
	.owner = THIS_MODULE,
	.open = fbd_open,
	.release = fbd_release,
	.media_changed = fbd_media_changed,
	.revalidate_disk = fbd_revalidate,
	.ioctl = fbd_ioctl,
};

static int setup_device(struct fbd_dev *dev, int which)
{
	memset (dev, 0, sizeof (struct fbd_dev));
	dev->size = N_SECTORS*FBD_SECTOR_SIZE;

	spin_lock_init(&dev->lock);
	
	dev->queue = blk_alloc_queue(GFP_KERNEL);
	if (dev->queue == NULL) {
		pr_err("Error: unable to alloc memory for queue for device %d\n", which);
		return -ENOMEM;
	}
	blk_queue_make_request(dev->queue, fbd_make_request);
	
	blk_queue_logical_block_size(dev->queue, FBD_SECTOR_SIZE);
	dev->queue->queuedata = dev;

	dev->gd = alloc_disk(2);
	if (!dev->gd) {
		pr_err("Error: unable to alloc disk for device %d\n", which);
		return -ENOMEM;
	}
	dev->gd->major = fake_block_dev_major;
	dev->gd->first_minor = 0;
	dev->gd->fops = &fbd_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	
	snprintf (dev->gd->disk_name, 32, "fbd%c", which + '0');
	set_capacity(dev->gd, N_SECTORS*FBD_SECTOR_SIZE);
	add_disk(dev->gd);
	
	return 0;
}

static int char_dev_open(struct inode *inode, struct file *filp)
{
	is_char_dev_open = true;
	return 0;
}

static int char_dev_release(struct inode *inode, struct file *filp)
{
	is_char_dev_open = false;
	return 0;
}

static size_t read_sector_from_internal_buffer(char *buf)
{
	size_t tmp_len;
	size_t remaining_len = FBD_SECTOR_SIZE;
	unsigned long stop_jiffies = jiffies + msecs_to_jiffies(MAX_DATA_READY_TIMEOUT);
	
	pr_debug("%s\n", __func__);
	
	data_buffer.fill_buffer = true;
	
	// wait until there's enough data to transfer in the buffer
	while (data_buffer.valid_bytes < remaining_len) {
		// if char device is not open or closed unexpectedly, then fill the output
		// buffer with zeros and return
		if (is_char_dev_open == false) {
			memset(buf, 0, remaining_len);
			pr_warn("Warning: char dev is not open. Filling with zeros\n");
			return remaining_len;
		}
		pr_debug("not enough data in the buffer. Wait\n");
		mdelay(5);
		
		if (time_is_before_eq_jiffies(stop_jiffies)) {
			pr_warn("Warning: timeout reached without incoming data. Filling with zeros\n");
			memset(buf, 0, remaining_len);
			return remaining_len;
		} 
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
	
	pr_debug("%s: buffer is %ld/%d full - write_idx=%d - read_idx=%d", __func__, data_buffer.valid_bytes, VMALLOC_SIZE, data_buffer.write_idx, data_buffer.read_idx);
	
	mutex_unlock(&(data_buffer.lock_mutex));
	
	return FBD_SECTOR_SIZE;
}

static ssize_t char_dev_read(struct file *filp, char *buffer, size_t len, loff_t *off)
{
	return -EINVAL;
};

static ssize_t char_dev_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	size_t tmp_len;
	size_t remaining_len = len;
	
	pr_debug("%s: writing %ld bytes\n", __func__, len);
	
	if (!data_buffer.fill_buffer) {
		pr_debug("%s: no one is reading the file. Skip buffer filling\n", __func__);
		return len;
	}
	
	mutex_lock(&(data_buffer.lock_mutex));
	
	while (remaining_len > 0) {
		tmp_len = min((size_t)(VMALLOC_SIZE - data_buffer.write_idx), remaining_len);
		
		copy_from_user(&(data_buffer.data[data_buffer.write_idx]), buf, tmp_len);
		
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
	
	pr_debug("%s: buffer is %ld/%d full - write_idx=%d - read_idx=%d", __func__, data_buffer.valid_bytes, VMALLOC_SIZE, data_buffer.write_idx, data_buffer.read_idx);
	
	return len;
}

static struct file_operations char_dev_fops = {
	.owner = THIS_MODULE,
	.read = char_dev_read,
	.write = char_dev_write,
	.open = char_dev_open,
	.release = char_dev_release
};

static int create_character_device(void)
{
	int ret;
	dev_t tmp_id;
	
	ret = alloc_chrdev_region(&char_dev_id, 0, 1, "fbd_char_dev");
	if (ret < 0) {
		pr_err("Error: alloc_chrdev_region() failed\n");
		return ret;
	}
	
	fbd_cdev = cdev_alloc();
	if (fbd_cdev == NULL) {
		pr_err("Error: cdev_alloc() failed\n");
		goto fail_1;
	}
	cdev_init(fbd_cdev, &char_dev_fops);
	fbd_cdev->owner = THIS_MODULE;
	
	tmp_id = MKDEV(MAJOR(char_dev_id), 0);  // only 1 minor
	ret = cdev_add(fbd_cdev, tmp_id, 1);
	if (ret < 0) {
		pr_err("Error: cdev_add() failed\n");
		goto fail_1;
	}
	
	char_dev_class = class_create(THIS_MODULE, "fbd_class");
	if (IS_ERR(char_dev_class)) {
		pr_err("Error: class_create() failed\n");
		ret = PTR_ERR(char_dev_class);
		goto fail_2;
	}
	
	fbd_char_dev = device_create(char_dev_class, NULL, tmp_id, NULL, "fbd_cdev");
	if(fbd_char_dev == NULL ) {
		pr_err("Error: device_create() failed\n");
		goto fail_3;
	}
	
	mutex_init(&(data_buffer.lock_mutex));
	
	return 0;

fail_3:
	class_destroy(char_dev_class);
	
fail_2:
	cdev_del(fbd_cdev);

fail_1:
	unregister_chrdev_region(char_dev_id, 1);
	return ret;
}

static int remove_character_device(void)
{
	if (char_dev_id > 0) {
		dev_t tmp_id = MKDEV(MAJOR(char_dev_id), 0);
		pr_info("Destroy char_dev_id\n");
		device_destroy(char_dev_class, tmp_id);
	}
	
	if (char_dev_class) {
		pr_info("Destroy char_dev_class\n");
		class_destroy(char_dev_class);
	}
	
	if (fbd_cdev) {
		pr_info("Removing fbd_cdev\n");
		cdev_del(fbd_cdev);
	}
	
	if (char_dev_id > 0) {
		pr_info("Unregister char_dev_id\n");
		unregister_chrdev_region(char_dev_id, 1);
	}
		
	return 0;
}

static int __init fbd_init(void)
{
	int ret;

	fake_block_dev_major = register_blkdev(fake_block_dev_major, "fbd");
	if (fake_block_dev_major <= 0) {
		pr_err("Error: unable to get major number\n");
		return -EBUSY;
	}

	device_ptr = kzalloc(sizeof (struct fbd_dev), GFP_KERNEL);
	if (device_ptr == NULL) {
		pr_err("Error: unable to allocate memory for devices\n");
		goto out_unregister;
	}
	
	ret = setup_device(device_ptr, 0);
	if (ret < 0) {
		goto out_unregister;
	}
	
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
	
	ret = create_character_device();
	if (ret < 0) {
		goto out_unregister;
	}
	pr_debug("Allocated internal buffer of %d bytes\n", VMALLOC_SIZE); 
	
	pr_info("init completed successfully\n");
	
	return 0;

out_unregister:
	pr_err("Error: init failed. Unregister all\n");
	unregister_blkdev(fake_block_dev_major, "sbd");
	remove_character_device();
	if (data_buffer.data != NULL) {
		vfree(data_buffer.data);
	}
	return -ENOMEM;
}

static void __exit fbd_exit(void)
{
	remove_character_device();
	if (data_buffer.data != NULL) {
		vfree(data_buffer.data);
	}
	
	if (device_ptr->gd) {
		del_gendisk(device_ptr->gd);
		put_disk(device_ptr->gd);
	}
	
	if (device_ptr->queue) {
		kobject_put (&device_ptr->queue->kobj);
	}
	
	unregister_blkdev(fake_block_dev_major, "fbd");
	kfree(device_ptr);
	
	pr_info("exit\n");
}
	
module_init(fbd_init);
module_exit(fbd_exit);

MODULE_LICENSE("GPL");
