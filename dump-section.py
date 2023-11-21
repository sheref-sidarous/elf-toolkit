from elftools.elf.elffile import ELFFile
import sys
import struct

import sys
from elftools.elf.elffile import ELFFile
from elftools.dwarf.lineprogram import LineProgram

from dwarf_decode_address import decode_file_line

def addr2line(elf_file, target_addr):
    # Find the relevant section for the address
    for section in elf_file.iter_sections():
        if not section['sh_addr'] <= target_addr < section['sh_addr'] + section['sh_size']:
            continue

        # Find the corresponding line program
        for cu in elf_file.get_dwarf_info().iter_CUs():
            if cu['unit_type'] == 'DW_UT_compile':
                lineprog = cu.get_entries()
                break

        # Find the line number information for the address
        for entry in lineprog:
            if entry.state is not None and entry.state.address <= target_addr:
                file_name = cu.get_file_entry(entry.state.file - 1).name.decode('utf-8')
                line_number = entry.state.line
                return f"{file_name}:{line_number}"

    return f"??:0"

def decode_selfref(base, value) :
    if value & 0x8000_0000:
        # this is an absolute value
        return value
    else:
        # the value is an offset with resepct to the base
        sign_extended_offset = value
        if value & 0x4000_0000:
            sign_extended_offset |= 0x8000_0000

        return (base + sign_extended_offset) & 0xffff_ffff

def dump_exception_index_table(base_addr, contents, elf_file):
    index = 0
    dwarf_info = elf_file.get_dwarf_info()
    while index * 8 < len(contents):
        start = index * 8
        fn_offset, content = struct.unpack("<II", contents[start:start+8])
        fn_offset = decode_selfref(base_addr + start, fn_offset)
        file, line = decode_file_line(dwarf_info, fn_offset)
        print(f"{index}: 0x{fn_offset:08x}, 0x{content:08x}, {file}:{line}")
        index += 1



def dump_section_contents(file_path, section_name):
    with open(file_path, 'rb') as file:
        # Create ELFFile object
        elf_file = ELFFile(file)

        # Iterate over sections
        for section in elf_file.iter_sections():
            if section.name == section_name:
                print(f"Dumping contents of section: {section.name}")

                # Get the section's offset and size
                offset = section['sh_offset']
                size = section['sh_size']
                base_address = section['sh_addr']


                # Seek to the beginning of the section in the file
                file.seek(offset)

                # Read and print the contents of the section
                section_contents = file.read(size)
                dump_exception_index_table(base_address, section_contents, elf_file)

                return

        print(f"Section '{section_name}' not found in the ELF file.")

# Example usage
file_path = sys.argv[1]
section_name = '.ARM'  # Replace with the desired section name
dump_section_contents(file_path, section_name)
