#!/bin/python
import argparse
import subprocess
from shlex import split
from dataclasses import dataclass
import concurrent.futures
import logging

logging.basicConfig(format="<%(levelname)s> %(message)s")
logger = logging.getLogger("wyze_whisper")
logger.setLevel(logging.INFO)

parser = argparse.ArgumentParser()

parser.add_argument(
    "--mode",
    required=True,
    choices=["pack", "unpack", "make", "cleanup"],
    help="Mode to use [pack, unpack, make]",
)
parser.add_argument(
    "--binary",
    required=False,
    help=("Binary to [pack, unkpack] " + "(only use with --mode [pack, unpack])\n"),
)
parser.add_argument(
    "-V", "--verbose", action="store_true", help="Enable verbose logging (LEVEL: DEBUG)"
)

args = parser.parse_args()


@dataclass(frozen=True)
class FirmwarePart:
    """Dataclass representing a firmware part"""

    name: str
    offset: hex
    size: hex

    def __str__(self):
        keywords = [f"{key} - {value!r} |" for key, value in self.__dict__.items()]
        return "".join(keywords)


def get_firmware_parts() -> list[FirmwarePart]:
    """Create a list of FirmwarePart objects"""
    _parts = [
        ("uimage_header", 0x0, 0x40),
        ("uimage_kernel", 0x40, 0x200000),
        ("squashfs_1", 0x200040, 0x350000),
        ("squashfs_2", 0x550040, 0xA0000),
        ("jffs2", 0x5F0040, 11075648 - 0x5F0040),
    ]
    firmware_parts = [FirmwarePart(*part) for part in _parts]
    for part in firmware_parts:
        logger.debug(f"Prepared part: {part}")
    return firmware_parts


def cleanup(firmware_parts) -> None:
    logger.info("[CLEAN UP] Removing junk binaries.")
    for part in firmware_parts:
        subprocess.Popen(split(f"rm {part.name}"))
        logger.debug(f"[CLEANUP] Removed {part.name}")
    logger.info("[CLEAN UP] Operation completed.")


def make_fsystem() -> None:
    """Create filesystem"""
    args_ = split("unsquashfs -s squashfs_1")
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


def unpack(firmware_parts) -> None:
    """Handles the firmware unpacking operation"""
    for part in firmware_parts:
        with open(args.binary, "rb") as bin:
            bin.seek(part.offset)
            data = bin.read(part.size)

        with open(part.name, "wb") as out:
            out.write(data)

        logger.debug(f"Wrote {part.name} - {len(data)} bytes")
    args_ = [
        split("unsquashfs -d squashfs_1_out squashfs_1"),
        split("unsquashfs -d squashfs_2_out squashfs_2"),
        split("jefferson -d jffs2_out jffs2"),
    ]
    with concurrent.futures.ThreadPoolExecutor() as executor:
        logger.debug("[UNPACK] Scheduling commands:")
        for arg in args_:
            logger.debug(" ".join(arg), end="\n")
        futures = [
            executor.submit(subprocess.Popen, arg, stdout=subprocess.DEVNULL)
            for arg in args_
        ]
        concurrent.futures.wait(futures)
        for future in futures:
            future.result().wait()
        logger.info("[UNPACK] Operation complete")


def pack(firmware_parts) -> None:
    """
    Handles the creation of the final file system.
    To achieve this it combines the kernel with the other file systems
    """
    for part in firmware_parts[1:]:
        with open(part.name, "rb") as f:
            data = f.read(part.size)

        with open(args.binary, "wb") as bin:
            bin.write(data)
            padding = part.size - len(data)

            logger.debug(f"Wrote {part.name} - {(len(data))} bytes")
            logger.debug(f"Padding: {hex(padding)}")
            bin.write(b"\x00" * padding)
            logger.info("Padding operation success")


def main(args) -> None:
    try:
        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logging.warning(
            "[!!!] this tool is for educational purposes only. never use in the wild without explicitly written permission."
        )

        if args.binary is None and args.mode in ["pack", "unpack"]:
            raise argparse.argumenterror(
                message=f"Unspecified binary to {args.mode}", argument=args.binary
            )

        firmware_parts = get_firmware_parts()
        if args.mode == "unpack":
            unpack(firmware_parts)
        if args.mode == "pack":
            pack(firmware_parts)
            cleanup(firmware_parts)
        if args.mode == "make":
            make_fsystem()
        if args.mode == "cleanup":
            logger.info("[TOTAL CLEANUP] Starting")
            cleanup(firmware_parts)
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [
                    executor.submit(
                        subprocess.Popen,
                        split(f"rm -rf {f}"),
                        stdout=subprocess.DEVNULL,
                    )
                    for f in ("squashfs_1_out", "squashfs_2_out", "jffs2_out")
                ]
                concurrent.futures.wait(futures)
                for future in futures:
                    future.result().wait()
            logger.info("[TOTAL CLEANUP] Operation completed.")

    except KeyboardInterrupt:
        raise KeyboardInterrupt("Received keyboard interrupt.")


if __name__ == "__main__":
    main(args)
