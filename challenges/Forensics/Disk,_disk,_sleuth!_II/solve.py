#!/usr/bin/env python3
"""
Solve script for Disk, disk, sleuth! II (#137)
Category: Forensics
"""
import gzip
import os
from pathlib import Path
import re
import struct

def parse_connection_cfg(cfg_path="connection.cfg"):
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    return cfg

def ensure_disk_image(img_path="dds2-alpine.flag.img", gz_path="dds2-alpine.flag.img.gz"):
    if not os.path.exists(img_path):
        if os.path.exists(gz_path):
            print(f"[*] Decompressing {gz_path}...", flush=True)
            with gzip.open(gz_path, "rb") as f_in, open(img_path, "wb") as f_out:
                while chunk := f_in.read(1024 * 1024):
                    f_out.write(chunk)
            print(f"[+] Decompressed to {img_path}", flush=True)
        else:
            raise FileNotFoundError(f"Neither {img_path} nor {gz_path} found.")
    return img_path

def extract_flag_from_image(img_path):
    with open(img_path, "rb") as f:
        # Read MBR to find Partition 1 offset
        mbr = f.read(512)
        p1_entry = mbr[446:446 + 16]
        lba_start = int.from_bytes(p1_entry[8:12], "little")
        part_offset = lba_start * 512
        print(f"[*] Partition 1 start: LBA {lba_start} (offset {part_offset})", flush=True)

        # Read Ext2 superblock
        f.seek(part_offset + 1024)
        sb = f.read(1024)
        s_magic = struct.unpack("<H", sb[56:58])[0]
        if s_magic != 0xef53:
            raise ValueError(f"Unexpected filesystem magic: {hex(s_magic)}")

        s_log_block_size = struct.unpack("<I", sb[24:28])[0]
        block_size = 1024 << s_log_block_size
        s_inodes_per_group = struct.unpack("<I", sb[40:44])[0]
        s_inode_size = struct.unpack("<H", sb[88:90])[0]

        print(f"[*] Block size: {block_size}, Inodes per group: {s_inodes_per_group}, Inode size: {s_inode_size}", flush=True)

        # Search for directory entry for down-at-the-bottom.txt
        f.seek(0)
        target_name = b"down-at-the-bottom.txt"
        img_bytes = f.read()
        target_pos = img_bytes.find(target_name)
        if target_pos == -1:
            raise FileNotFoundError("Could not find down-at-the-bottom.txt in disk image")

        # In ext directory entry:
        # offset 0..3: inode (uint32)
        # offset 4..5: rec_len (uint16)
        # offset 6: name_len (uint8)
        # offset 7: file_type (uint8)
        # offset 8..: name
        entry_start = target_pos - 8
        target_inode = int.from_bytes(img_bytes[entry_start:entry_start + 4], "little")
        print(f"[*] Found directory entry for {target_name.decode()}: inode {target_inode}", flush=True)

        # Locate inode table and inode data
        bg_idx = (target_inode - 1) // s_inodes_per_group
        idx_in_bg = (target_inode - 1) % s_inodes_per_group

        # Block group descriptor table starts at block 2 when block size is 1024 (or block 1 if >1024)
        bgdt_block = 2 if block_size == 1024 else 1
        f.seek(part_offset + bgdt_block * block_size + bg_idx * 32)
        bgd = f.read(32)
        bg_inode_table = struct.unpack("<III", bgd[0:12])[2]

        inode_offset = part_offset + bg_inode_table * block_size + idx_in_bg * s_inode_size
        f.seek(inode_offset)
        inode_data = f.read(s_inode_size)

        i_mode, i_uid, i_size = struct.unpack("<HHI", inode_data[0:8])
        direct_blocks = struct.unpack("<12I", inode_data[40:40 + 48])
        print(f"[*] File size: {i_size} bytes, data block: {direct_blocks[0]}", flush=True)

        # Read file data
        f.seek(part_offset + direct_blocks[0] * block_size)
        file_content = f.read(i_size).decode("utf-8", errors="ignore")

        # Parse ASCII bubble text: ( c )
        chars = re.findall(r"\(\s*(.)\s*\)", file_content)
        flag = "".join(chars).strip()
        return flag

def solve():
    print("[*] Solving Disk, disk, sleuth! II...", flush=True)
    cfg = parse_connection_cfg()
    img_path = ensure_disk_image()
    flag = extract_flag_from_image(img_path)

    print(f"[+] Flag: {flag}", flush=True)
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    return flag

if __name__ == "__main__":
    solve()
