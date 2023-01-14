#include <common.h>
#include <command.h>

static int do_flock(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	return(sfc_flash_lock(argc, argv));
}

U_BOOT_CMD(
	flock,	CONFIG_SYS_MAXARGS,	1,	do_flock,
	"norflash lock-3.0",
	"<data>\n"
	"      <data> -- (0x00-0x3c)Block Protection Bit(BP).\n"
	"                refers to the value written to status registers.\n"
  "                the default address for writting:0x01.\n"
	"                the written value preserves only the BP bit ,which usually is [5:2]\n\n"

  "flock status\n"
  "             -- this command is to examine the data of the status register\n"
  "                the default address for reading:0x05\n\n"

  "flock FR <WREN> <WR> <WD>\n"
  "         <WREN> -- refers to the command of Write Enable.\n"
  "         <WR>   -- refers to the address of the write register.\n"
  "         <WD>   -- refers to the data written.\n\n"

  "flock RR <addr>\n"
  "         <addr> -- refers to the address of the read register.\n\n"
);
