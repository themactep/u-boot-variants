#include <common.h>
#include <environment.h>
#include <command.h>
#include <malloc.h>
#include <image.h>
#include <asm/byteorder.h>
#include <asm/io.h>
#include <spi_flash.h>
#include <linux/mtd/mtd.h>
#include <fat.h>
#include <part.h>
#include "../lib/crypto/crypto.h"

#ifdef CONFIG_AUTO_UPDATE  /* cover the whole file */

#ifdef CONFIG_AUTO_SD_UPDATE
#ifndef CONFIG_MMC
#error "should have defined CONFIG_MMC"
#endif
#include <mmc.h>
#endif

/* possible names of files on the medium. */
#define AU_UBOOT	"u-boot"
#define AU_KERNEL	"kernel"
#define AU_ROOTFS	"rootfs"
#define AU_APP	    "app"
#define AU_KBACK	"kback"
#define AU_ABACK	"aback"
#define AU_CFG	    "cfg"
#define AU_PARA	    "para"
#define AU_FW		"demo_wcv3.bin"

/* layout of the FLASH. ST = start address, ND = end address. */
#define AU_FL_UBOOT_ST		0x0
#define AU_FL_UBOOT_ND		0x40000
#define AU_FL_KERNEL_ST		0x40000
#define AU_FL_KERNEL_ND		0x230000
#define AU_FL_ROOTFS_ST		0x230000
#define AU_FL_ROOTFS_ND		0x600000
#define AU_FL_APP_ST		0x600000
#define AU_FL_APP_ND		0x9d0000
#define AU_FL_KBACK_ST		0x9d0000
#define AU_FL_KBACK_ND		0xbc0000
#define AU_FL_RABACK_ST		0xbc0000
#define AU_FL_RABACK_ND		0xf90000
#define AU_FL_CFG_ST		0xf90000
#define AU_FL_CFG_ND		0xff0000
#define AU_FL_PARA_ST		0xff0000
#define AU_FL_PARA_ND		0x1000000

#define AU_FL_FW_ST			0x40000
#define AU_FL_FW_ND			0x9d0000

#define AU_FL_FW_ND			0x9d0000

/* where to load files into memory */
#define LOAD_ADDR ((unsigned char *)0x82000000)
#define POFFSET_ADDR ((unsigned char *)0x83000000)
#define PPOFFSET_ADDR ((unsigned char *)0x84000000)

/* Waiting time 2s */
#define WAIT_SECS	2

/* length of the signature */
#ifdef CONFIG_AUTO_UPDATE_CRYPTO
#define SIGNATURE	64
/*#define NETUP_SIGN*/
#else
#define SIGNATURE	0
#endif

#if defined (CONFIG_PRODUCT_WYZEV2PAN) 
#define RESET_GPIO 	6
#else
#define RESET_GPIO 	51
#endif

/* index of each file in the following arrays */
enum IDX
{
	IDX_UBOOT, IDX_KERNEL, IDX_ROOTFS, IDX_APP, IDX_KBACK, IDX_RABACK, IDX_CFG, IDX_PARA, IDX_FW
};

/* pointers to file names */
char *aufile[] = {
	AU_UBOOT,
	AU_KERNEL,
	AU_ROOTFS,
	AU_APP,
	AU_KBACK,
	AU_ABACK,
	AU_CFG,
	AU_PARA,
	AU_FW,
};

/* sizes of flash areas for each file */
unsigned long ausize[] = {
	AU_FL_UBOOT_ND - AU_FL_UBOOT_ST,
	AU_FL_KERNEL_ND - AU_FL_KERNEL_ST,
	AU_FL_ROOTFS_ND - AU_FL_ROOTFS_ST,
	AU_FL_APP_ND - AU_FL_APP_ST,
	AU_FL_KBACK_ND - AU_FL_KBACK_ST,
	AU_FL_RABACK_ND - AU_FL_RABACK_ST,
	AU_FL_CFG_ND - AU_FL_CFG_ST,
	AU_FL_PARA_ND - AU_FL_PARA_ST,
	AU_FL_FW_ND - AU_FL_FW_ST,
};

static struct spi_flash *flash;

static int au_check_cksum_valid(int idx, long nbytes)
{
	image_header_t *hdr = (image_header_t *)LOAD_ADDR;
	unsigned long checksum;

	if(nbytes != (sizeof(*hdr) + ntohl(hdr->ih_size)))
	{
		printf("sizeof(*hdr) + ntohl(hdr->ih_size):%d\n",(sizeof(*hdr) + ntohl(hdr->ih_size)));
		printf("nbytes:%d\n",nbytes);
		printf("Image %s bad total SIZE\n", aufile[idx]);
		return -1;
	}

	/* check the data CRC */
	checksum = ntohl(hdr->ih_dcrc);
	if(crc32(0, (unsigned char const *)(LOAD_ADDR + sizeof(*hdr)), ntohl(hdr->ih_size)) != checksum)
	{
		printf("Image %s bad data checksum\n", aufile[idx]);
		return -1;
	}

	return 0;
}

static int au_check_header_valid(int idx, long nbytes)
{
	image_header_t *hdr;
	unsigned long checksum;
	hdr = (image_header_t *)LOAD_ADDR;

#undef CHECK_VALID_DEBUG
#ifdef CHECK_VALID_DEBUG
	printf("\nmagic %#x %#x\n", ntohl(hdr->ih_magic), IH_MAGIC);
	printf("arch %#x %#x\n", hdr->ih_arch, IH_ARCH_MIPS);
	printf("size %#x %#lx\n", ntohl(hdr->ih_size), nbytes);
	printf("type %#x %#x\n", hdr->ih_type, IH_TYPE_FIRMWARE);
#endif

	if(nbytes < sizeof(*hdr))
	{
		printf("Image %s bad header SIZE\n", aufile[idx]);
		return -1;
	}

	if(ntohl(hdr->ih_magic) != IH_MAGIC || hdr->ih_arch != IH_ARCH_MIPS)
	{
		printf("Image %s bad MAGIC or ARCH\n", aufile[idx]);
		return -1;
	}

	/* check the hdr CRC */
	checksum = ntohl(hdr->ih_hcrc);
	hdr->ih_hcrc = 0;
	if(crc32(0, (unsigned char const *)hdr, sizeof(*hdr)) != checksum)
	{
		printf("Image %s bad header checksum\n", aufile[idx]);
		return -1;
	}

	hdr->ih_hcrc = htonl(checksum);
	/* check the type - could do this all in one gigantic if() */
	if((idx == IDX_UBOOT) && (hdr->ih_type != IH_TYPE_FIRMWARE))
	{
		printf("Image %s wrong type\n", aufile[idx]);
		return -1;
	}
	else if((idx == IDX_KERNEL) && (hdr->ih_type != IH_TYPE_KERNEL))
	{
		printf("Image %s wrong type\n", aufile[idx]);
		return -1;
	}
	else if((idx == IDX_ROOTFS) &&
			(hdr->ih_type != IH_TYPE_RAMDISK) && (hdr->ih_type != IH_TYPE_FILESYSTEM))
	{
		printf("Image %s wrong type\n", aufile[idx]);
		return -1;
	}
	else if((idx == IDX_APP) &&
			(hdr->ih_type != IH_TYPE_RAMDISK) && (hdr->ih_type != IH_TYPE_FILESYSTEM))
	{
		printf("Image %s wrong type\n", aufile[idx]);
		return -1;
	}
	else if((idx == IDX_FW) && (hdr->ih_type != IH_TYPE_FIRMWARE))
	{
		printf("Image %s wrong type\n", aufile[idx]);
		return -1;
	}

	/* recycle checksum */
	checksum = ntohl(hdr->ih_size);
	/* for kernel and app the image header must also fit into flash */
	if((idx == IDX_KERNEL) && (idx == IH_TYPE_RAMDISK))
		checksum += sizeof(*hdr);

	/* check the size does not exceed space in flash. HUSH scripts */
	if((ausize[idx] != 0) && (ausize[idx] < checksum))
	{
		printf("Image %s is bigger than FLASH\n", aufile[idx]);
		return -1;
	}

	return 0;
}

static int mmc_au_do_update(int idx)
{
	image_header_t *hdr;
	unsigned long write_len;
	void *buf;
	char *pbuf;
	int rc = 0;
	hdr = (image_header_t *)LOAD_ADDR;

	//set the blue led to on
	rc = gpio_request(GPIO_PB(7), "blue_gpio");
	rc = gpio_direction_output(GPIO_PB(7), 0);

	printf("flash erase...\n");
	rc = flash->erase(flash, AU_FL_FW_ST, ausize[idx]);
	if(rc)
	{
		printf("SPI flash sector erase failed\n");
		return 1;
	}

	buf = map_physmem((unsigned long)LOAD_ADDR, sizeof(*hdr)+ausize[idx], MAP_WRBACK);
	if(!buf)
	{
		printf("Failed to map physical memory\n");
		return 1;
	}

	/* strip the header - except for the kernel and ramdisk */
	if (hdr->ih_type == IH_TYPE_KERNEL || hdr->ih_type == IH_TYPE_RAMDISK)
	{
		pbuf = buf;
		write_len = sizeof(*hdr) + ntohl(hdr->ih_size);
	}
	else
	{
		pbuf = (buf + sizeof(*hdr));
		write_len = ntohl(hdr->ih_size);
	}

	/* copy the data from RAM to FLASH */
	printf("flash write...\n");
	rc = flash->write(flash, AU_FL_FW_ST, write_len, pbuf);
	if(rc)
	{
		printf("SPI flash write failed, return %d\n", rc);
		return 1;
	}

	/* check the dcrc of the copy */
	if(crc32(0, (unsigned char const *)(buf + sizeof(*hdr)), ntohl(hdr->ih_size)) != ntohl(hdr->ih_dcrc))
	{
		printf("Image %s Bad Data Checksum After COPY\n", aufile[idx]);
		return -1;
	}

	unmap_physmem(buf, sizeof(*hdr)+ausize[idx]);
	rc = gpio_direction_output(GPIO_PB(7), 1);

	return 0;
}

static int mmc_update_to_flash(int idx)
{
	int res = 0;
	long sz = 0;

	/* just read the header */
	sz = file_fat_read(aufile[idx], LOAD_ADDR, sizeof(image_header_t));
	debug("read %s sz %ld hdr %d\n", aufile[idx], sz, sizeof(image_header_t));
	if(sz <= 0 || sz < sizeof(image_header_t))
	{
		debug("%s not found\n", aufile[idx]);
		return -1;
	}

	if (au_check_header_valid(idx, sz) < 0)
	{
		debug("%s header not valid\n", aufile[idx]);
		return -1;
	}

	sz = file_fat_read(aufile[idx], LOAD_ADDR, ausize[idx]+SIGNATURE);
	debug("read %s sz %ld hdr %d\n", aufile[idx], sz, sizeof(image_header_t));
	if (sz <= 0 || sz <= sizeof(image_header_t))
	{
		debug("%s not found\n", aufile[idx]);
		return -1;
	}

#ifdef CONFIG_AUTO_UPDATE_CRYPTO
	if(0 != eddsa_verify(LOAD_ADDR, sz))
	{
		printf("%s sigh verify fail\n", aufile[idx]);
		return -1;
	}
	printf("%s sigh verify success\n", aufile[idx]);
	sz -= 64;
#endif

	if (au_check_cksum_valid(idx, sz) < 0)
	{
		debug("%s checksum not valid\n", aufile[idx]);
		return -1;
	}

	res = mmc_au_do_update(idx);

	return res;
}

static int au_do_update(void)
{
	int i = 0, j = 0;
	char *bufSignature = NULL;
	char *buf = (char *)LOAD_ADDR;
	char *pbuf = (char *)PPOFFSET_ADDR;
	char *ppbuf = (char *)POFFSET_ADDR;
	unsigned char *signature[128] = {0};

	if(flash->read(flash, AU_FL_PARA_ST, ausize[IDX_PARA], buf))
	{
		printf("Failed to map physical memory\n");
		return 1;
	}
	else
	{

#if (defined(CONFIG_AUTO_UPDATE_CRYPTO) && defined(NETUP_SIGN))
		while(1)
		{
			if(strncmp(buf+j, "SIGNATURE=", 10) == 0)
			{
				memcpy(signature, buf+j, SIGNATURE);
				printf("Read signature successfully!\n");
				break;
			}
			j++;
			i++;
			if(i == (ausize[IDX_PARA])-10)
			{
				printf("Read signature failed, signature cannot be found!\n");
				return 1;
			}
		}
		j = 0;
		i = 0;
#endif
		while(1)
		{
			if(strncmp(buf+j, "FWGRADEUP=", 10) == 0)
			{
				buf = buf+j;
				printf("Find the upgrade flag!\n");
				break;
			}
			j++;
			i++;
			if(i == (ausize[IDX_PARA])-10)
			{
				printf("The upgrade flag could not be found!\n");
				return 1;
			}
		}

		if(strncmp(buf+10, "kernel+app", 10) == 0)
		{
			printf("FWGRADEUP=kernel+app!\n");
			if(flash->read(flash, AU_FL_KBACK_ST, ausize[IDX_KBACK], pbuf))
			{
				printf("Failed to map physical memory\n");
				return 1;
			}

			printf("aback flash read...\n");
			if(flash->read(flash, AU_FL_RABACK_ST, ausize[IDX_RABACK], ppbuf))
			{
				printf("Failed to map physical memory\n");
				return 1;
			}

			memcpy(pbuf+ausize[IDX_KBACK], ppbuf, ausize[IDX_RABACK]);

#if (defined(CONFIG_AUTO_UPDATE_CRYPTO) && defined(NETUP_SIGN))
			memcpy(pbuf+ausize[IDX_KBACK]+ausize[IDX_RABACK], signature, SIGNATURE);
			if(0 != eddsa_verify(pbuf, ausize[IDX_KBACK]+ausize[IDX_RABACK]+SIGNATURE))
			{
				printf("Signature verification failed\n");
				return 1;
			}
			printf("Signature verification success\n");
#endif

			printf("kenral flash erase...\n");
			if(flash->erase(flash, AU_FL_KERNEL_ST, ausize[IDX_KERNEL]))
			{
				printf("SPI kernel flash sector erase failed\n");
				return 1;
			}

			printf("kernel flash write...\n");
			if(flash->write(flash, AU_FL_KERNEL_ST, ausize[IDX_KERNEL], pbuf))
			{
				printf("SPI kernel flash write failed\n");
				return 1;
			}

			printf("app flash erase...\n");
			if(flash->erase(flash, AU_FL_APP_ST, ausize[IDX_APP]))
			{
				printf("SPI app flash sector erase failed\n");
				return 1;
			}

			printf("app flash write...\n");
			if(flash->write(flash, AU_FL_APP_ST, ausize[IDX_APP], pbuf+ausize[IDX_KERNEL]))
			{
				printf("SPI drivers flash write failed\n");
				return 1;
			}
		}
		else if(strncmp(buf+10, "kernel+rootfs", 13) == 0)
		{
			printf("FWGRADEUP=kernel+rootfs!\n");
			if(flash->read(flash, AU_FL_KBACK_ST, ausize[IDX_KBACK]+ausize[IDX_RABACK], pbuf))
			{
				printf("Failed to map physical memory\n");
				return 1;
			}

#if (defined(CONFIG_AUTO_UPDATE_CRYPTO) && defined(NETUP_SIGN))
			memcpy(pbuf+ausize[IDX_KBACK]+ausize[IDX_RABACK], signature, SIGNATURE);
			if(0 != eddsa_verify(pbuf, ausize[IDX_KBACK]+ausize[IDX_RABACK]+SIGNATURE))
			{
				printf("Signature verification failed\n");
				return 1;
			}
			printf("Signature verification success\n");
#endif

			printf("kenral flash erase...\n");
			if(flash->erase(flash, AU_FL_KERNEL_ST, ausize[IDX_KERNEL]+ausize[IDX_ROOTFS]))
			{
				printf("SPI kernel+rootfs flash sector erase failed\n");
				return 1;
			}

			printf("kernel flash write...\n");
			if(flash->write(flash, AU_FL_KERNEL_ST, ausize[IDX_KERNEL]+ausize[IDX_ROOTFS], pbuf))
			{
				printf("SPI kernel flash write failed\n");
				return 1;
			}
		}
		else if(strncmp(buf+10, "kernel", 6) == 0)
		{
			printf("FWGRADEUP=Kernel!\n");
			if(flash->read(flash, AU_FL_KBACK_ST, ausize[IDX_KBACK], pbuf))
			{
				printf("Failed to map physical memory\n");
				return 1;
			}

#if (defined(CONFIG_AUTO_UPDATE_CRYPTO) && defined(NETUP_SIGN))
			memcpy(pbuf+ausize[IDX_KBACK], signature, SIGNATURE);
			if(0 != eddsa_verify(pbuf, ausize[IDX_KBACK]+SIGNATURE))
			{
				printf("Signature verification failed\n");
				return 1;
			}
			printf("Signature verification success\n");
#endif

			printf("Kernal flash erase...\n");
			if(flash->erase(flash, AU_FL_KERNEL_ST, ausize[IDX_KERNEL]))
			{
				printf("SPI kernal flash sector erase failed\n");
				return 1;
			}

			printf("Kernal flash write...\n");
			if(flash->write(flash, AU_FL_KERNEL_ST, ausize[IDX_KERNEL], pbuf))
			{
				printf("SPI kernal flash write failed\n");
				return 1;
			}
		}
		else if(strncmp(buf+10, "rootfs", 6) == 0)
		{
			printf("FWGRADEUP=rootfs!\n");
			if(flash->read(flash, AU_FL_RABACK_ST, ausize[IDX_RABACK], pbuf))
			{
				printf("Failed to map physical memory\n");
				return 1;
			}

#if (defined(CONFIG_AUTO_UPDATE_CRYPTO) && defined(NETUP_SIGN))
			memcpy(pbuf+ausize[IDX_RABACK], signature, SIGNATURE);
			if(0 != eddsa_verify(pbuf, ausize[IDX_RABACK]+SIGNATURE))
			{
				printf("Signature verification failed\n");
				return 1;
			}
			printf("Signature verification success\n");
#endif

			printf("drivers flash erase...\n");
			if(flash->erase(flash, AU_FL_ROOTFS_ST, ausize[IDX_ROOTFS]))
			{
				printf("SPI rootfs flash sector erase failed\n");
				return 1;
			}

			printf("drivers flash write...\n");
			if(flash->write(flash, AU_FL_ROOTFS_ST, ausize[IDX_ROOTFS], pbuf))
			{
				printf("SPI rootfs flash write failed\n");
				return 1;
			}
		}
		else if(strncmp(buf+10, "app", 3) == 0)
		{
			printf("FWGRADEUP=app!\n");
			if(flash->read(flash, AU_FL_RABACK_ST, ausize[IDX_RABACK], pbuf))
			{
				printf("Failed to map physical memory\n");
				return 1;
			}

#if (defined(CONFIG_AUTO_UPDATE_CRYPTO) && defined(NETUP_SIGN))
			memcpy(pbuf+ausize[IDX_RABACK], signature, SIGNATURE);
			if(0 != eddsa_verify(pbuf, ausize[IDX_RABACK]+SIGNATURE))
			{
				printf("Signature verification failed\n");
				return 1;
			}
			printf("Signature verification success\n");
#endif

			printf("app flash erase...\n");
			if(flash->erase(flash, AU_FL_APP_ST, ausize[IDX_APP]))
			{
				printf("SPI app flash sector erase failed\n");
				return 1;
			}

			printf("app flash write...\n");
			if(flash->write(flash, AU_FL_APP_ST, ausize[IDX_APP], pbuf))
			{
				printf("SPI rootfs flash write failed\n");
				return 1;
			}
		}
		printf("flag flash earse...\n");
		if(flash->erase(flash, AU_FL_PARA_ST, ausize[IDX_PARA]))
		{
			printf("SPI flash sector erase failed\n");
			return 1;
		}
	}
	return 0;
}

static int do_check_sd(void)
{
	int ret = 0;
	block_dev_desc_t *stor_dev;
	
	stor_dev = get_dev("mmc", 0);
	if(NULL == stor_dev)
	{
		printf("SD card is not insert\n");
		return -1;
	}

	ret = fat_register_device(stor_dev, 1);
	if(0 != ret)
	{
		printf("fat_register_device fail\n");
		return -1;
	}

	ret = file_fat_detectfs();
	if (0 != ret) 
	{
		printf("file_fat_detectfs fail\n");
		return -1;
	}
	printf("file_fat_detectfs OK\n");

	return 0;
}

/*
 * This is called by board_init() after the hardware has been set up
 * and is usable. Only if SPI flash initialization failed will this function
 * return -1, otherwise it will return 0;
 */
int do_auto_update(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	int old_ctrlc;
	int m,n;
	int choose = 0;
	int state = -1;
	unsigned int ret = 0;

	gpio_request(RESET_GPIO, "sdupgrade");
	gpio_direction_input(RESET_GPIO);
	ret = gpio_get_value(RESET_GPIO) & 0x1;
	if(ret == 0)
	{
		for(m = 0; m < WAIT_SECS; m++)
		{
			for (n = 0; n < 1000; n++)
			{
				udelay(1000);	//wait 1 ms
			}
		}				
		ret = gpio_get_value(RESET_GPIO) & 0x1;
		if(ret == 0)
		{
			choose = 1;		
		}
	}

	/*
	 * make sure that we see CTRL-C
	 * and save the old state
	 */
	old_ctrlc = disable_ctrlc(0);

	/*
	 * CONFIG_SF_DEFAULT_SPEED=1000000,
	 * CONFIG_SF_DEFAULT_MODE=0x3
	 */
	flash = spi_flash_probe(0, 0, 1000000, 0x3);
	if(!flash)
	{
		printf("Failed to initialize SPI flash\n");
		return -1;
	}
	if(choose)
	{
		if(0 != do_check_sd()) return -1;
		state = mmc_update_to_flash(IDX_FW);
	}
	else
	{
		state = au_do_update();
	}
	/* restore the old state */
	disable_ctrlc(old_ctrlc);

	return 0;
}

U_BOOT_CMD(
	sdupdate, 1, 0, do_auto_update,
	"auto upgrade file!",
	" "
);
#endif /* CONFIG_AUTO_UPDATE */
