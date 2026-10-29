"""Parse block dumps captured by run_blk.py."""
import struct
import sys
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'blk_out.bin')

def parse():
    if not os.path.exists(OUT):
        print("blk_out.bin not found")
        return
    raw = open(OUT, 'rb').read()
    print(f"Total raw size: {len(raw)} bytes")
    
    # Check for marker
    marker = b'=== BLK ===\n'
    idx = raw.find(marker)
    if idx == -1:
        print("Marker === BLK === not found in output.")
        text = raw.decode('latin-1', 'replace')
        print("Captured text:", repr(text[:200]))
        return
    
    data = raw[idx + len(marker):]
    end_marker = b'\n=== BLK_END ==='
    end_idx = data.find(end_marker)
    if end_idx != -1:
        data = data[:end_idx]
    
    print(f"Extracted block payload: {len(data)} bytes")
    with open(os.path.join(HERE, 'extracted_blk.bin'), 'wb') as f:
        f.write(data)
    
    # Check if this is the persistent_properties block
    # It contains 'persist.' strings
    if b'persist.' in data:
        print("\n[*** IDENTIFIED PERSISTENT_PROPERTIES DATA BLOCK! ***]")
        with open(os.path.join(HERE, 'persistent_properties_block_519807.bin'), 'wb') as f:
            f.write(data)
        
        # Find all persist properties
        print("\nPropriedades encontradas no arquivo:")
        strings = re.findall(b'[\x20-\x7e]{4,}', data)
        for s in strings:
            s_str = s.decode('latin-1', 'replace')
            if 'persist' in s_str or 'usb' in s_str or 'adb' in s_str or 'config' in s_str:
                print(f"  {s_str}")
        
        print("\nArquivo salvo com sucesso em 'persistent_properties_block_519807.bin'!")
        return

    # Check if this block contains Inode 57459 at offset 512
    if len(data) >= 512 + 256:
        inod = data[512:512+256]
        mode, uid, size_lo = struct.unpack_from('<HHI', inod, 0)
        flags = struct.unpack_from('<I', inod, 0x20)[0]
        links = struct.unpack_from('<H', inod, 0x1a)[0]
        if mode != 0 and (mode & 0o170000) == 0o100000:
            print(f"\n[*** PARSED INODE 57459 (persistent_properties) ***]")
            print(f"  Mode: {oct(mode)} UID: {uid} Size: {size_lo} bytes Links: {links}")
            with open(os.path.join(HERE, 'prop_inode_57459.bin'), 'wb') as f:
                f.write(inod)
            
            i_block = inod[0x28:0x28+60]
            magic, entries, max_entries, depth = struct.unpack_from('<HHHH', i_block, 0)
            if magic == 0xf30a and depth == 0:
                for k in range(entries):
                    off = 12 + k * 12
                    ee_blk, ee_len, ee_hi, ee_lo = struct.unpack_from('<IHHI', i_block, off)
                    pblk = (ee_hi << 32) | ee_lo
                    print(f"  --> PHYSICAL DATA BLOCK: {pblk} (length: {ee_len} blocks)")
            return

if __name__ == '__main__':
    parse()
