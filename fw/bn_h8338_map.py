from typing import *
from binaryninja import *

bv: BinaryView

rw  = ( SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable )
rx  = ( SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable )
rwx = ( rw | SegmentFlag.SegmentExecutable )

inrom = ( SegmentFlag.SegmentContainsCode | rx )
rwdat = ( SegmentFlag.SegmentContainsData | rw )
rodat = ( SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentDenyWrite )

'''
3.1.1 Mode Selection

The H8/338 Series operates in three modes numbered 1, 2, and 3. The mode is selected by the
inputs at the mode pins (MD 1 and MD 0) when the chip comes out of a reset. See table 3.1.

Modes 1 and 2 are expanded modes that permit access to off-chip memory and peripheral devices.
The maximum address space supported by these externally expanded modes is 64K bytes.

In mode 3 (single-chip mode), only on-chip ROM and RAM and the on-chip register field are
used. All ports are available for general-purpose input and output.
'''
memmaps = {
    # tuple format:
    # <base>, <len>, <offset>, <len>, <seg_flags>, <sec_flags>, <name>

    # 48k ROM
    #  2k RAM
    "H8/338" : {
        # Single-Chip Mode
        3 : [
            (0x0000, 0x0048, 0x0000, 0x0048, rodat, SectionSemantics.ReadOnlyDataSectionSemantics,  "Vector Table"),
            (0x0048, 0xBFB8, 0x0048, 0xBFB8, inrom, SectionSemantics.ReadOnlyCodeSectionSemantics,  "On-Chip ROM" ),
            (0xC000, 0x3780, 0xC000, 0x3780, 0x000, SectionSemantics.DefaultSectionSemantics,       "Unused 0"    ),
            (0xF780, 0x0800, 0xF780, 0x0800, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip RAM" ),
            (0xFF80, 0x0008, 0xFF80, 0x0008, 0x000, SectionSemantics.DefaultSectionSemantics,       "Unused 1"    ),
            (0xFF88, 0x0078, 0xFF88, 0x0078, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip Regs"),
        ],
        # Expanded Mode with On-Chip ROM
        2 : [
            (0x0000, 0x0048, 0x0000, 0x0048, rodat, SectionSemantics.ReadOnlyDataSectionSemantics,  "Vector Table" ),
            (0x0048, 0xBFB8, 0x0048, 0xBFB8, inrom, SectionSemantics.ReadOnlyCodeSectionSemantics,  "On-Chip ROM"  ),
            (0xC000, 0x3780, 0xC000, 0x3780,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 0"),
            (0xF780, 0x0800, 0xF780, 0x0800, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip RAM"  ),
            (0xFF80, 0x0008, 0xFF80, 0x0008,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 1"),
            (0xFF88, 0x0078, 0xFF88, 0x0078, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip Regs" ),
        ],
        # Expanded Mode without On-Chip ROM
        1 : [
            (0x0000, 0x0048, 0x0000, 0x0048, rodat, SectionSemantics.ReadOnlyDataSectionSemantics,  "Vector Table" ),
            (0x0048, 0xF738, 0x0048, 0xF738,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 0"),
            (0xF780, 0x0800, 0xF780, 0x0800, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip RAM"  ),
            (0xFF80, 0x0008, 0xFF80, 0x0008,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 1"),
            (0xFF88, 0x0078, 0xFF88, 0x0078, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip Regs" ),
        ],
    },

    # 32k ROM
    #  1k RAM
    "H8/337" : {
        # Single-Chip Mode
        3 : [
            (0x0000, 0x0048, 0x0000, 0x0048, rodat, SectionSemantics.ReadOnlyDataSectionSemantics,  "Vector Table"),
            (0x0048, 0x7FB8, 0x0048, 0x7FB8, inrom, SectionSemantics.ReadOnlyCodeSectionSemantics,  "On-Chip ROM" ),
            (0x8000, 0x7B80, 0x8000, 0x7B80, 0x000, SectionSemantics.DefaultSectionSemantics,       "Unused 0"    ),
            (0xFB80, 0x0400, 0xFB80, 0x0400, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip RAM" ),
            (0xFF80, 0x0008, 0xFF80, 0x0008, 0x000, SectionSemantics.DefaultSectionSemantics,       "Unused 1"    ),
            (0xFF88, 0x0078, 0xFF88, 0x0078, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip Regs"),
        ],
        # Expanded Mode with On-Chip ROM
        2 : [
            (0x0000, 0x0048, 0x0000, 0x0048, rodat, SectionSemantics.ReadOnlyDataSectionSemantics,  "Vector Table" ),
            (0x0048, 0x7FB8, 0x0048, 0x7FB8, inrom, SectionSemantics.ReadOnlyCodeSectionSemantics,  "On-Chip ROM"  ),
            (0x8000, 0x4000, 0x8000, 0x4000, 0x000, SectionSemantics.DefaultSectionSemantics,       "Reserved 0"   ),
            (0xC000, 0x3780, 0xC000, 0x3780,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 0"),
            (0xF780, 0x0400, 0xF780, 0x0400, 0x000, SectionSemantics.DefaultSectionSemantics,       "Reserved 1"   ),
            (0xFB80, 0x0400, 0xFB80, 0x0400, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip RAM"  ),
            (0xFF80, 0x0008, 0xFF80, 0x0008,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 1"),
            (0xFF88, 0x0078, 0xFF88, 0x0078, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip Regs" ),
        ],
        # Expanded Mode without On-Chip ROM
        1 : [
            (0x0000, 0x0048, 0x0000, 0x0048, rodat, SectionSemantics.ReadOnlyDataSectionSemantics,  "Vector Table" ),
            (0x0048, 0xF738, 0x0048, 0xF738,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 0"),
            (0xF780, 0x0400, 0xF780, 0x0400, 0x000, SectionSemantics.DefaultSectionSemantics,       "Reserved 0"   ),
            (0xFB80, 0x0400, 0xFB80, 0x0400, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip RAM"  ),
            (0xFF80, 0x0008, 0xFF80, 0x0008,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 1"),
            (0xFF88, 0x0078, 0xFF88, 0x0078, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip Regs" ),
        ],
    },
    
    # 24k ROM
    #  1k RAM
    "H8/336" : {
        # Single-Chip Mode
        3 : [
            (0x0000, 0x0048, 0x0000, 0x0048, rodat, SectionSemantics.ReadOnlyDataSectionSemantics,  "Vector Table"),
            (0x0048, 0x5FB8, 0x0048, 0x5FB8, inrom, SectionSemantics.ReadOnlyCodeSectionSemantics,  "On-Chip ROM" ),
            (0x6000, 0x9B80, 0x6000, 0x9B80, 0x000, SectionSemantics.DefaultSectionSemantics,       "Unused 0"    ),
            (0xFB80, 0x0400, 0xFB80, 0x0400, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip RAM" ),
            (0xFF80, 0x0008, 0xFF80, 0x0008, 0x000, SectionSemantics.DefaultSectionSemantics,       "Unused 1"    ),
            (0xFF88, 0x0078, 0xFF88, 0x0078, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip Regs"),
        ],
        # Expanded Mode with On-Chip ROM
        2 : [
            (0x0000, 0x0048, 0x0000, 0x0048, rodat, SectionSemantics.ReadOnlyDataSectionSemantics,  "Vector Table" ),
            (0x0048, 0x5FB8, 0x0048, 0x5FB8, inrom, SectionSemantics.ReadOnlyCodeSectionSemantics,  "On-Chip ROM"  ),
            (0x6000, 0x6000, 0x6000, 0x6000, 0x000, SectionSemantics.DefaultSectionSemantics,       "Reserved 0"   ),
            (0xC000, 0x3780, 0xC000, 0x3780,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 0"),
            (0xF780, 0x0400, 0xF780, 0x0400, 0x000, SectionSemantics.DefaultSectionSemantics,       "Reserved 1"   ),
            (0xFB80, 0x0400, 0xFB80, 0x0400, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip RAM"  ),
            (0xFF80, 0x0008, 0xFF80, 0x0008,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 1"),
            (0xFF88, 0x0078, 0xFF88, 0x0078, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip Regs" ),
        ],
        # Expanded Mode without On-Chip ROM
        1 : [
            (0x0000, 0x0048, 0x0000, 0x0048, rodat, SectionSemantics.ReadOnlyDataSectionSemantics,  "Vector Table" ),
            (0x0048, 0xF738, 0x0048, 0xF738,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 0"),
            (0xF780, 0x0400, 0xF780, 0x0400, 0x000, SectionSemantics.DefaultSectionSemantics,       "Reserved 0"   ),
            (0xFB80, 0x0400, 0xFB80, 0x0400, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip RAM"  ),
            (0xFF80, 0x0008, 0xFF80, 0x0008,   rwx, SectionSemantics.ExternalSectionSemantics,      "Ext Address 1"),
            (0xFF88, 0x0078, 0xFF88, 0x0078, rwdat, SectionSemantics.ReadWriteDataSectionSemantics, "On-Chip Regs" ),
        ],
    },
}

def init_h83xx_map(dev_map: dict[dict[list]], op_mode: int):
    try:
        # Mode 0 is inoperative in H8/338 Series. 
        # Avoid setting the mode pins to mode 0.
        assert(0 < op_mode <= 3)

        # Create corresponding segments & sections.
        for s in dev_map[op_mode]:
            bv.add_auto_segment(*s[:-2]) # splat lol...
            bv.add_auto_section(s[-1], *s[:2], s[-2])

    except Exception as e:
        print(e)
        pass

if __name__ == "__main__":
    fn = bv.file.original_filename
    # JEOL seem to be using H8/338 in Single-Chip Mode ?
    if any(s in fn for s in ["EOS", "EVAC", "HT", "LV"]):
        init_h83xx_map(memmaps["H8/338"], op_mode=3)
