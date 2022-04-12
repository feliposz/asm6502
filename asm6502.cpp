#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

enum address_mode
{
    address_mode_undef,
    address_mode_acc, // can merge with imp?
    address_mode_imp,
    address_mode_imm,
    address_mode_zp,
    address_mode_zp_x,
    address_mode_zp_y,
    address_mode_rel,
    address_mode_abs,
    address_mode_abs_x,
    address_mode_abs_y,
    address_mode_ind,
    address_mode_ind_x,
    address_mode_ind_y,
};

struct opcode
{
    const char *mnemonic;
    int length;
    address_mode mode;
};

opcode opcodes[256];

inline void init_opcode(int id, const char *mnemonic, int length, address_mode mode)
{
    opcodes[id].mnemonic = mnemonic;
    opcodes[id].length = length;
    opcodes[id].mode = mode;
}

int disasm_single(unsigned char *bytes, int offset, int base_address, FILE *file)
{
    int id = bytes[offset];
    const char *mnemonic = opcodes[id].mnemonic;
    address_mode mode = opcodes[id].mode;

    unsigned int address = offset + base_address;
    unsigned int byte = bytes[offset + 1];
    unsigned int word = (bytes[offset + 2] << 8) | (bytes[offset + 1] & 0xff);
    unsigned int rel = offset + base_address + 2 + (signed char)byte;

    fprintf(file, "$%04x    ", address);

    if (opcodes[id].length == 3)
    {
        fprintf(file, "%02x %02x %02x  ", bytes[offset], bytes[offset + 1], bytes[offset + 2]);
    }
    else if (opcodes[id].length == 2)
    {
        fprintf(file, "%02x %02x     ", bytes[offset], bytes[offset + 1]);
    }
    else
    {
        fprintf(file, "%02x        ", bytes[offset]);
    }

    switch (mode)
    {
        case address_mode_abs:
            fprintf(file, "%s $%04x\n", mnemonic, word);
            break;
        case address_mode_abs_x:
            fprintf(file, "%s $%04x,X\n", mnemonic, word);
            break;
        case address_mode_abs_y:
            fprintf(file, "%s $%04x,Y\n", mnemonic, word);
            break;
        case address_mode_imp:
            fprintf(file, "%s\n", mnemonic);
            break;
        case address_mode_acc:
            fprintf(file, "%s A\n", mnemonic);
            break;
        case address_mode_imm:
            fprintf(file, "%s #$%02x\n", mnemonic, byte);
            break;
        case address_mode_ind:
            fprintf(file, "%s ($%04x)\n", mnemonic, word);
            break;
        case address_mode_ind_x:
            fprintf(file, "%s ($%02x,X)\n", mnemonic, byte);
            break;
        case address_mode_ind_y:
            fprintf(file, "%s ($%02x),Y\n", mnemonic, byte);
            break;
        case address_mode_rel:
            fprintf(file, "%s $%04x\n", mnemonic, rel);
            break;
        case address_mode_zp:
            fprintf(file, "%s $%02x\n", mnemonic, byte);
            break;
        case address_mode_zp_x:
            fprintf(file, "%s $%02x,X\n", mnemonic, byte);
            break;
        case address_mode_zp_y:
            fprintf(file, "%s $%02x,Y\n", mnemonic, byte);
            break;
        default:
            assert(!"invalid code path");
            break;
    }

    return opcodes[id].length;
}

void disasm_program(unsigned char *bytes, int size, int base_address, FILE *file)
{
    fprintf(file, "Address  Hexdump   Dissassembly\n");
    fprintf(file, "-------------------------------\n");
    for (int offset = 0; offset < size; )
    {
        offset += disasm_single(bytes + base_address, offset, base_address, file);
    }
}

void init()
{
    for (int i = 0; i < 256; i++)
    {
        init_opcode(i, "???", 1, address_mode_imp);
    }

    init_opcode(0x69, "ADC", 2, address_mode_imm);
    init_opcode(0x65, "ADC", 2, address_mode_zp);
    init_opcode(0x75, "ADC", 2, address_mode_zp_x);
    init_opcode(0x6D, "ADC", 3, address_mode_abs);
    init_opcode(0x7D, "ADC", 3, address_mode_abs_x);
    init_opcode(0x79, "ADC", 3, address_mode_abs_y);
    init_opcode(0x61, "ADC", 2, address_mode_ind_x);
    init_opcode(0x71, "ADC", 2, address_mode_ind_y);
    init_opcode(0x29, "AND", 2, address_mode_imm);
    init_opcode(0x25, "AND", 2, address_mode_zp);
    init_opcode(0x35, "AND", 2, address_mode_zp_x);
    init_opcode(0x2D, "AND", 3, address_mode_abs);
    init_opcode(0x3D, "AND", 3, address_mode_abs_x);
    init_opcode(0x39, "AND", 3, address_mode_abs_y);
    init_opcode(0x21, "AND", 2, address_mode_ind_x);
    init_opcode(0x31, "AND", 2, address_mode_ind_y);
    init_opcode(0x0A, "ASL", 1, address_mode_acc);
    init_opcode(0x06, "ASL", 2, address_mode_zp);
    init_opcode(0x16, "ASL", 2, address_mode_zp_x);
    init_opcode(0x0E, "ASL", 3, address_mode_abs);
    init_opcode(0x1E, "ASL", 3, address_mode_abs_x);
    init_opcode(0x24, "BIT", 2, address_mode_zp);
    init_opcode(0x2C, "BIT", 3, address_mode_abs);
    init_opcode(0x00, "BRK", 1, address_mode_imp);
    init_opcode(0xC9, "CMP", 2, address_mode_imm);
    init_opcode(0xC5, "CMP", 2, address_mode_zp);
    init_opcode(0xD5, "CMP", 2, address_mode_zp_x);
    init_opcode(0xCD, "CMP", 3, address_mode_abs);
    init_opcode(0xDD, "CMP", 3, address_mode_abs_x);
    init_opcode(0xD9, "CMP", 3, address_mode_abs_y);
    init_opcode(0xC1, "CMP", 2, address_mode_ind_x);
    init_opcode(0xD1, "CMP", 2, address_mode_ind_y);
    init_opcode(0xE0, "CPX", 2, address_mode_imm);
    init_opcode(0xE4, "CPX", 2, address_mode_zp);
    init_opcode(0xEC, "CPX", 3, address_mode_abs);
    init_opcode(0xC0, "CPY", 2, address_mode_imm);
    init_opcode(0xC4, "CPY", 2, address_mode_zp);
    init_opcode(0xCC, "CPY", 3, address_mode_abs);
    init_opcode(0xC6, "DEC", 2, address_mode_zp);
    init_opcode(0xD6, "DEC", 2, address_mode_zp_x);
    init_opcode(0xCE, "DEC", 3, address_mode_abs);
    init_opcode(0xDE, "DEC", 3, address_mode_abs_x);
    init_opcode(0x42, "WDM", 2, address_mode_imm); // 65C816
    init_opcode(0x49, "EOR", 2, address_mode_imm);
    init_opcode(0x45, "EOR", 2, address_mode_zp);
    init_opcode(0x55, "EOR", 2, address_mode_zp_x);
    init_opcode(0x4D, "EOR", 3, address_mode_abs);
    init_opcode(0x5D, "EOR", 3, address_mode_abs_x);
    init_opcode(0x59, "EOR", 3, address_mode_abs_y);
    init_opcode(0x41, "EOR", 2, address_mode_ind_x);
    init_opcode(0x51, "EOR", 2, address_mode_ind_y);
    init_opcode(0xE6, "INC", 2, address_mode_zp);
    init_opcode(0xF6, "INC", 2, address_mode_zp_x);
    init_opcode(0xEE, "INC", 3, address_mode_abs);
    init_opcode(0xFE, "INC", 3, address_mode_abs_x);
    init_opcode(0x4C, "JMP", 3, address_mode_abs);
    init_opcode(0x6C, "JMP", 3, address_mode_ind);
    init_opcode(0x20, "JSR", 3, address_mode_abs);
    init_opcode(0xA9, "LDA", 2, address_mode_imm);
    init_opcode(0xA5, "LDA", 2, address_mode_zp);
    init_opcode(0xB5, "LDA", 2, address_mode_zp_x);
    init_opcode(0xAD, "LDA", 3, address_mode_abs);
    init_opcode(0xBD, "LDA", 3, address_mode_abs_x);
    init_opcode(0xB9, "LDA", 3, address_mode_abs_y);
    init_opcode(0xA1, "LDA", 2, address_mode_ind_x);
    init_opcode(0xB1, "LDA", 2, address_mode_ind_y);
    init_opcode(0xA2, "LDX", 2, address_mode_imm);
    init_opcode(0xA6, "LDX", 2, address_mode_zp);
    init_opcode(0xB6, "LDX", 2, address_mode_zp_y);
    init_opcode(0xAE, "LDX", 3, address_mode_abs);
    init_opcode(0xBE, "LDX", 3, address_mode_abs_y);
    init_opcode(0xA0, "LDY", 2, address_mode_imm);
    init_opcode(0xA4, "LDY", 2, address_mode_zp);
    init_opcode(0xB4, "LDY", 2, address_mode_zp_x);
    init_opcode(0xAC, "LDY", 3, address_mode_abs);
    init_opcode(0xBC, "LDY", 3, address_mode_abs_x);
    init_opcode(0x4A, "LSR", 1, address_mode_acc);
    init_opcode(0x46, "LSR", 2, address_mode_zp);
    init_opcode(0x56, "LSR", 2, address_mode_zp_x);
    init_opcode(0x4E, "LSR", 3, address_mode_abs);
    init_opcode(0x5E, "LSR", 3, address_mode_abs_x);
    init_opcode(0xEA, "NOP", 1, address_mode_imp);
    init_opcode(0x09, "ORA", 2, address_mode_imm);
    init_opcode(0x05, "ORA", 2, address_mode_zp);
    init_opcode(0x15, "ORA", 2, address_mode_zp_x);
    init_opcode(0x0D, "ORA", 3, address_mode_abs);
    init_opcode(0x1D, "ORA", 3, address_mode_abs_x);
    init_opcode(0x19, "ORA", 3, address_mode_abs_y);
    init_opcode(0x01, "ORA", 2, address_mode_ind_x);
    init_opcode(0x11, "ORA", 2, address_mode_ind_y);
    init_opcode(0x2A, "ROL", 1, address_mode_acc);
    init_opcode(0x26, "ROL", 2, address_mode_zp);
    init_opcode(0x36, "ROL", 2, address_mode_zp_x);
    init_opcode(0x2E, "ROL", 3, address_mode_abs);
    init_opcode(0x3E, "ROL", 3, address_mode_abs_x);
    init_opcode(0x6A, "ROR", 1, address_mode_acc);
    init_opcode(0x66, "ROR", 2, address_mode_zp);
    init_opcode(0x76, "ROR", 2, address_mode_zp_x);
    init_opcode(0x6E, "ROR", 3, address_mode_abs);
    init_opcode(0x7E, "ROR", 3, address_mode_abs_x);
    init_opcode(0x40, "RTI", 1, address_mode_imp);
    init_opcode(0x60, "RTS", 1, address_mode_imp);
    init_opcode(0xE9, "SBC", 2, address_mode_imm);
    init_opcode(0xE5, "SBC", 2, address_mode_zp);
    init_opcode(0xF5, "SBC", 2, address_mode_zp_x);
    init_opcode(0xED, "SBC", 3, address_mode_abs);
    init_opcode(0xFD, "SBC", 3, address_mode_abs_x);
    init_opcode(0xF9, "SBC", 3, address_mode_abs_y);
    init_opcode(0xE1, "SBC", 2, address_mode_ind_x);
    init_opcode(0xF1, "SBC", 2, address_mode_ind_y);
    init_opcode(0x85, "STA", 2, address_mode_zp);
    init_opcode(0x95, "STA", 2, address_mode_zp_x);
    init_opcode(0x8D, "STA", 3, address_mode_abs);
    init_opcode(0x9D, "STA", 3, address_mode_abs_x);
    init_opcode(0x99, "STA", 3, address_mode_abs_y);
    init_opcode(0x81, "STA", 2, address_mode_ind_x);
    init_opcode(0x91, "STA", 2, address_mode_ind_y);
    init_opcode(0x86, "STX", 2, address_mode_zp);
    init_opcode(0x96, "STX", 2, address_mode_zp_y);
    init_opcode(0x8E, "STX", 3, address_mode_abs);
    init_opcode(0x84, "STY", 2, address_mode_zp);
    init_opcode(0x94, "STY", 2, address_mode_zp_x);
    init_opcode(0x8C, "STY", 3, address_mode_abs);
    init_opcode(0x10, "BPL", 2, address_mode_rel);
    init_opcode(0x30, "BMI", 2, address_mode_rel);
    init_opcode(0x50, "BVC", 2, address_mode_rel);
    init_opcode(0x70, "BVS", 2, address_mode_rel);
    init_opcode(0x90, "BCC", 2, address_mode_rel);
    init_opcode(0xB0, "BCS", 2, address_mode_rel);
    init_opcode(0xD0, "BNE", 2, address_mode_rel);
    init_opcode(0xF0, "BEQ", 2, address_mode_rel);
    init_opcode(0xAA, "TAX", 1, address_mode_imp);
    init_opcode(0x8A, "TXA", 1, address_mode_imp);
    init_opcode(0xCA, "DEX", 1, address_mode_imp);
    init_opcode(0xE8, "INX", 1, address_mode_imp);
    init_opcode(0xA8, "TAY", 1, address_mode_imp);
    init_opcode(0x98, "TYA", 1, address_mode_imp);
    init_opcode(0x88, "DEY", 1, address_mode_imp);
    init_opcode(0xC8, "INY", 1, address_mode_imp);
    init_opcode(0x18, "CLC", 1, address_mode_imp);
    init_opcode(0x38, "SEC", 1, address_mode_imp);
    init_opcode(0x58, "CLI", 1, address_mode_imp);
    init_opcode(0x78, "SEI", 1, address_mode_imp);
    init_opcode(0xB8, "CLV", 1, address_mode_imp);
    init_opcode(0xD8, "CLD", 1, address_mode_imp);
    init_opcode(0xF8, "SED", 1, address_mode_imp);
    init_opcode(0x9A, "TXS", 1, address_mode_imp);
    init_opcode(0xBA, "TSX", 1, address_mode_imp);
    init_opcode(0x48, "PHA", 1, address_mode_imp);
    init_opcode(0x68, "PLA", 1, address_mode_imp);
    init_opcode(0x08, "PHP", 1, address_mode_imp);
    init_opcode(0x28, "PLP", 1, address_mode_imp);
}

void disasm_test()
{
    //unsigned char example[] = { 0xa9, 0xc0, 0xaa, 0xe8, 0x69, 0xc4, 0x00 };
    //unsigned char example[] = { 0xa9, 0x00, 0x8d, 0x00, 0x02, 0xa9, 0x01, 0x8d, 0x01, 0x02, 0x8d, 0xff, 0x05 };
    //unsigned char example[] = { 0xa9, 0x80, 0x85, 0x01, 0x65, 0x01, 0xa9, 0xf1, 0xaa, 0xa9, 0xf2, 0xa8, 0xa9, 0x00, 0x98, 0x8a };
    //unsigned char example[] = { 0xa9, 0x03, 0x85, 0x00, 0xa9, 0x09, 0x38, 0xe5, 0x00, 0x85, 0x01 };
    //unsigned char example[] = { 0xa2, 0x08, 0xca, 0x8e, 0x00, 0x02, 0xe0, 0x03, 0xf0, 0x03, 0x4c, 0x02, 0x06, 0x8e, 0x01, 0x02 };
    //unsigned char example[] = { 0xa2, 0x08, 0xca, 0x8e, 0x00, 0x02, 0xe0, 0x03, 0xd0, 0xf8, 0x8e, 0x01, 0x02, 0x00, 0xff };
    //unsigned char example[] = { 0xa2, 0x02, 0x8e, 0x00, 0x02, 0xa9, 0xf0, 0x6d, 0x00, 0x02, 0x90, 0xfb, 0x8e, 0x01, 0x02, 0x00 };
    //unsigned char example[] = { 0xa2, 0x00, 0xa0, 0x00, 0x8a, 0x99, 0x00, 0x02, 0x48, 0xe8, 0xc8, 0xc0, 0x10, 0xd0, 0xf5, 0x68, 0x99, 0x00, 0x02, 0xc8, 0xc0, 0x20, 0xd0, 0xf7 };
    //unsigned char example[] = { 0x20, 0x09, 0x06, 0x20, 0x0c, 0x06, 0x20, 0x12, 0x06, 0xa2, 0x00, 0x60, 0xe8, 0xe0, 0x05, 0xd0, 0xfb, 0x60, 0x00 };
    //unsigned char example[] = { 0x20, 0x06, 0x06, 0x20, 0x38, 0x06, 0x20, 0x0d, 0x06, 0x20, 0x2a, 0x06, 0x60, 0xa9, 0x02, 0x85, 0x02, 0xa9, 0x04, 0x85, 0x03, 0xa9, 0x11, 0x85, 0x10, 0xa9, 0x10, 0x85, 0x12, 0xa9, 0x0f, 0x85, 0x14, 0xa9, 0x04, 0x85, 0x11, 0x85, 0x13, 0x85, 0x15, 0x60, 0xa5, 0xfe, 0x85, 0x00, 0xa5, 0xfe, 0x29, 0x03, 0x18, 0x69, 0x02, 0x85, 0x01, 0x60, 0x20, 0x4d, 0x06, 0x20, 0x8d, 0x06, 0x20, 0xc3, 0x06, 0x20, 0x19, 0x07, 0x20, 0x20, 0x07, 0x20, 0x2d, 0x07, 0x4c, 0x38, 0x06, 0xa5, 0xff, 0xc9, 0x77, 0xf0, 0x0d, 0xc9, 0x64, 0xf0, 0x14, 0xc9, 0x73, 0xf0, 0x1b, 0xc9, 0x61, 0xf0, 0x22, 0x60, 0xa9, 0x04, 0x24, 0x02, 0xd0, 0x26, 0xa9, 0x01, 0x85, 0x02, 0x60, 0xa9, 0x08, 0x24, 0x02, 0xd0, 0x1b, 0xa9, 0x02, 0x85, 0x02, 0x60, 0xa9, 0x01, 0x24, 0x02, 0xd0, 0x10, 0xa9, 0x04, 0x85, 0x02, 0x60, 0xa9, 0x02, 0x24, 0x02, 0xd0, 0x05, 0xa9, 0x08, 0x85, 0x02, 0x60, 0x60, 0x20, 0x94, 0x06, 0x20, 0xa8, 0x06, 0x60, 0xa5, 0x00, 0xc5, 0x10, 0xd0, 0x0d, 0xa5, 0x01, 0xc5, 0x11, 0xd0, 0x07, 0xe6, 0x03, 0xe6, 0x03, 0x20, 0x2a, 0x06, 0x60, 0xa2, 0x02, 0xb5, 0x10, 0xc5, 0x10, 0xd0, 0x06, 0xb5, 0x11, 0xc5, 0x11, 0xf0, 0x09, 0xe8, 0xe8, 0xe4, 0x03, 0xf0, 0x06, 0x4c, 0xaa, 0x06, 0x4c, 0x35, 0x07, 0x60, 0xa6, 0x03, 0xca, 0x8a, 0xb5, 0x10, 0x95, 0x12, 0xca, 0x10, 0xf9, 0xa5, 0x02, 0x4a, 0xb0, 0x09, 0x4a, 0xb0, 0x19, 0x4a, 0xb0, 0x1f, 0x4a, 0xb0, 0x2f, 0xa5, 0x10, 0x38, 0xe9, 0x20, 0x85, 0x10, 0x90, 0x01, 0x60, 0xc6, 0x11, 0xa9, 0x01, 0xc5, 0x11, 0xf0, 0x28, 0x60, 0xe6, 0x10, 0xa9, 0x1f, 0x24, 0x10, 0xf0, 0x1f, 0x60, 0xa5, 0x10, 0x18, 0x69, 0x20, 0x85, 0x10, 0xb0, 0x01, 0x60, 0xe6, 0x11, 0xa9, 0x06, 0xc5, 0x11, 0xf0, 0x0c, 0x60, 0xc6, 0x10, 0xa5, 0x10, 0x29, 0x1f, 0xc9, 0x1f, 0xf0, 0x01, 0x60, 0x4c, 0x35, 0x07, 0xa0, 0x00, 0xa5, 0xfe, 0x91, 0x00, 0x60, 0xa6, 0x03, 0xa9, 0x00, 0x81, 0x10, 0xa2, 0x00, 0xa9, 0x01, 0x81, 0x10, 0x60, 0xa2, 0x00, 0xea, 0xea, 0xca, 0xd0, 0xfb, 0x60 };
    unsigned char example[] = { 0x20, 0x06, 0x06, 0x20, 0x37, 0x06, 0x20, 0x0d, 0x06, 0x20, 0x2a, 0x06, 0x60, 0xa9, 0x02, 0x85, 0x02, 0xa9, 0x04, 0x85, 0x03, 0xa9, 0x11, 0x85, 0x10, 0xa9, 0x10, 0x85, 0x12, 0xa9, 0x0f, 0x85, 0x14, 0xa9, 0x04, 0x85, 0x11, 0x85, 0x13, 0x85, 0x15, 0x60, 0xa5, 0xfe, 0x85, 0x00, 0xa5, 0xfe, 0x29, 0x03, 0x18, 0x69, 0x02, 0x85, 0x01, 0x20, 0x57, 0x06, 0x20, 0x43, 0x06, 0x20, 0x4a, 0x06, 0x4c, 0x37, 0x06, 0xa0, 0x00, 0xa5, 0xfe, 0x91, 0x00, 0x60, 0xa6, 0x03, 0xa9, 0x00, 0x81, 0x10, 0xa2, 0x00, 0xa9, 0x01, 0x81, 0x10, 0x60, 0xa6, 0x03, 0xca, 0x8a, 0xb5, 0x10, 0x95, 0x12, 0xca, 0x10, 0xf9, 0xa5, 0x02, 0x4a, 0xb0, 0x09, 0x4a, 0xb0, 0x19, 0x4a, 0xb0, 0x1f, 0x4a, 0xb0, 0x2f, 0xa5, 0x10, 0x38, 0xe9, 0x20, 0x85, 0x10, 0x90, 0x01, 0x60, 0xc6, 0x11, 0xa9, 0x01, 0xc5, 0x11, 0xf0, 0x26, 0x60, 0xe6, 0x10, 0xa9, 0x1f, 0x24, 0x10, 0xf0, 0x1d, 0x60, 0xa5, 0x10, 0x18, 0x69, 0x20, 0x85, 0x10, 0xb0, 0x01, 0x60, 0xe6, 0x11, 0xa9, 0x06, 0xc5, 0x11, 0xf0, 0x0a, 0x60, 0xc6, 0x10, 0xa9, 0x1f, 0x25, 0x10, 0xf0, 0x01, 0x60, 0x4c, 0xab, 0x06 };

    disasm_program(example, sizeof(example), 0x600, stdout);
}

struct parsed_line
{
    char label[64];
    char op[64];
    char args[256];
};

void parse_line(const char *line, int length, parsed_line *parsed)
{
    int start, end, pos = 0;

    memset(parsed, 0, sizeof(parsed_line));

    while ((line[pos] == ' ') || (line[pos] == '\t'))
    {
        pos++;
    }

    // special case - set address *=$12AB
    if ((line[pos] == '*') && (line[pos + 1] == '='))
    {
        parsed->op[0] = '*';
        pos += 2;
        start = pos;

        while ((line[pos] != ';') && (line[pos] != '\n') && (line[pos] != '\r') && (line[pos] != 0))
        {
            pos++;
        }
        end = pos;

        strncpy_s(parsed->args, sizeof(parsed->args), &line[start], end - start);
        return;
    }

    start = pos;
    while ((line[pos] == '_') || ((line[pos] >= 'A') && (line[pos] <= 'Z')) || ((line[pos] >= 'a') && (line[pos] <= 'z')) || ((line[pos] >= '0') && (line[pos] <= '9')))
    {
        pos++;
    }
    end = pos;

    while ((line[pos] == ' ') || (line[pos] == '\t'))
    {
        pos++;
    }

    if (line[pos] != ':')
    {
        strncpy_s(parsed->op, sizeof(parsed->op), &line[start], end - start);
    }
    else
    {
        strncpy_s(parsed->label, sizeof(parsed->label), &line[start], end - start);
        pos++;

        while ((line[pos] == ' ') || (line[pos] == '\t'))
        {
            pos++; 
        }

        start = pos;
        while ((line[pos] == '_') || ((line[pos] >= 'A') && (line[pos] <= 'Z')) || ((line[pos] >= 'a') && (line[pos] <= 'z')) || ((line[pos] >= '0') && (line[pos] <= '9')))
        {
            pos++;
        }
        end = pos;
        strncpy_s(parsed->op, sizeof(parsed->op), &line[start], end - start);
    }

    while ((line[pos] == ' ') || (line[pos] == '\t'))
    {
        pos++;
    }

    start = pos;
    while ((line[pos] != ';') && (line[pos] != '\n') && (line[pos] != '\r') && (line[pos] != 0))
    {
        pos++;
    }
    end = pos;

    strncpy_s(parsed->args, sizeof(parsed->args), &line[start], end - start);
}

struct symbol
{
    char *label;
    int offset;
    symbol *next;
};

symbol *labels = 0;
symbol *defines = 0;

// TODO: check for duplicate labels

symbol *add_symbol(symbol *list, char *text, int offset)
{
    symbol *s = (symbol *)malloc(sizeof(symbol));
    size_t size = strlen(text) + 1;
    s->label = (char *)malloc(size);
    strcpy_s(s->label, size, text);
    s->offset = offset;
    s->next = list;
    return s;
}

#define INVALID_ADDRESS 0xFFFFF

int lookup_symbol(symbol *list, const char *text)
{
    for (symbol *s = list; s; s = s->next)
    {
        if (_stricmp(text, s->label) == 0)
        {
            return s->offset;
        }
    }
    return INVALID_ADDRESS;
}

void free_symbols(symbol **list)
{
    for (symbol *s = *list, *next = 0; s; s = next)
    {
        next = s->next;
        free(s->label);
        free(s);
    }
    *list = 0;
}

int lookup(const char *text)
{
    int address = lookup_symbol(defines, text);
    if (address == INVALID_ADDRESS)
    {
        address = lookup_symbol(labels, text);
    }
    return address;
}

void print_symbols(symbol *list)
{
    for (symbol *s = list; s; s = s->next)
    {
        printf("%04x    %s\n", s->offset, s->label);
    }
}

int parse_value(const char *text)
{
    int value = 0;
    if (*text == '$')
    {
        text++; // skip hex prefix
        for (;;)
        {
            if ((*text >= '0') && (*text <= '9'))
            {
                value = value * 16 + (*text - '0');
                text++;
            }
            else if ((*text >= 'A') && (*text <= 'F'))
            {
                value = value * 16 + (*text - 'A' + 10);
                text++;
            }
            else if ((*text >= 'a') && (*text <= 'f'))
            {
                value = value * 16 + (*text - 'a' + 10);
                text++;
            }
            else
            {
                break;
            }
        }
    }
    else
    {
        for (;;)
        {
            if ((*text >= '0') && (*text <= '9'))
            {
                value = value * 10 + (*text - '0');
                text++;
            }
            else
            {
                break;
            }
        }
    }
    return value;
}

address_mode get_address_mode(const char *args, int *ptr_address)
{
    address_mode mode = address_mode_undef;
    int address = 0;
    const char *c = args;

#define _skip_spaces while ((*c == ' ') || (*c == '\t')) {c++;}

    _skip_spaces;

    if (*c == 0)
    {
        mode = address_mode_imp;
    }
    else if (((c[0] == 'A') || (c[0] == 'a')) && c[1] == 0)
    {
        mode = address_mode_acc;
        c++;
    }
    else if (*c == '#')
    {
        mode = address_mode_imm;
        c++;
    }
    else if (*c == '(')
    {
        mode = address_mode_ind;
        c++;
    }
    else
    {
        mode = address_mode_abs;
    }

    _skip_spaces;

    if (*c == '$')
    {
        address = parse_value(c);
        *c++;
        while (((*c >= '0') && (*c <= '9')) || ((*c >= 'A') && (*c <= 'F')) || ((*c >= 'a') && (*c <= 'f')))
        {
            c++;
        }
    }
    else if ((*c >= '0') && (*c <= '9'))
    {
        address = parse_value(c);
        while ((*c >= '0') && (*c <= '9'))
        {
            c++;
        }
    }
    else
    {
        bool label_lo = false;
        bool label_hi = false;
        if (*c == '<')
        {
            label_lo = true;
            c++;
        }
        else if (*c == '>')
        {
            label_hi = true;
            c++;
        }

        char lookup_str[64];
        int lookup_len = 0;
        while ((lookup_len < 63) && (*c == '_') || ((*c >= 'A') && (*c <= 'Z')) || ((*c >= 'a') && (*c <= 'z')) || ((*c >= '0') && (*c <= '9')))
        {
            lookup_str[lookup_len++] = *c++;
        }
        lookup_str[lookup_len] = 0;

        if (lookup_len)
        {
            address = lookup(lookup_str);
            if (label_lo)
            {
                address = address & 0xFF;
            }
            else if (label_hi)
            {
                address = (address >> 8) & 0xFF;
            }
        }
    }

    _skip_spaces;

    if (*c == ')')
    {
        c++;
        _skip_spaces;
        if (*c == ',')
        {
            c++;
            _skip_spaces;
            if ((*c == 'y') || (*c == 'Y'))
            {
                mode = address_mode_ind_y;
                *c++;
            }
        }
    }

    if (*c == ',')
    {
        c++;
        _skip_spaces;
        if (((*c == 'x') || (*c == 'X')) && (mode == address_mode_ind))
        {
            mode = address_mode_ind_x;
            c++;
            _skip_spaces;
            assert(*c == ')');
            c++;
        }
        else if (((*c == 'x') || (*c == 'X')) && (mode == address_mode_abs))
        {
            mode = address_mode_abs_x;
            c++;
        }
        else if (((*c == 'y') || (*c == 'Y')) && (mode == address_mode_abs))
        {
            mode = address_mode_abs_y;
            c++;
        }
        else
        {
            assert(!"invalid mode");
        }
    }

    _skip_spaces;

    assert(*c == 0);

    assert(mode != address_mode_undef);

    if (ptr_address)
    {
        *ptr_address = address;
    }
    return mode;
}

int translate_dcb(const char *args, unsigned char *out)
{
    int pos = 0;
    int length = 0;

    for (;;)
    {
        while ((args[pos] == ' ') || (args[pos] == '\t'))
        {
            pos++;
        }

        if (args[pos] != 0)
        {
            out[length++] = parse_value(args + pos);
        }

        while ((args[pos] != ',') && (args[pos] != '\n') && (args[pos] != 0))
        {
            pos++;
        }

        if ((args[pos] == '\n') || (args[pos] == 0))
        {
            break;
        }
        else if (args[pos] == ',')
        {
            pos++;
        }
    }

    return length;
}

int translate_instruction(const char *op, address_mode mode, int current_address, int parsed_address, unsigned char *out)
{
    for (int pass = 0; pass < 2; pass++)
    {
        for (int id = 0; id < 256; id++)
        {
            if (_stricmp(opcodes[id].mnemonic, op) == 0)
            {
                address_mode test_mode = mode;
                // special case: branch instructions have relative addressing
                if ((opcodes[id].mode == address_mode_rel) && (mode == address_mode_abs))
                {
                    test_mode = address_mode_rel;
                    parsed_address = parsed_address - current_address - 2;
                }
                else if ((opcodes[id].mode == address_mode_acc) && (mode == address_mode_imp))
                {
                    test_mode = address_mode_acc;
                }
                else if ((pass == 0) && (parsed_address <= 0xFF))
                {
                    // check for zp addressing only on first pass
                    if (mode == address_mode_abs)
                    {
                        test_mode = address_mode_zp;
                    }
                    else if (mode == address_mode_abs_x)
                    {
                        test_mode = address_mode_zp_x;
                    }
                    else if (mode == address_mode_abs_y)
                    {
                        test_mode = address_mode_zp_y;
                    }
                }
                if (opcodes[id].mode == test_mode)
                {
                    out[0] = id;
                    if (opcodes[id].length == 2)
                    {
                        out[1] = parsed_address & 0xFF;
                    }
                    else if (opcodes[id].length == 3)
                    {
                        out[1] = parsed_address & 0xFF;
                        out[2] = (parsed_address >> 8) & 0xFF;
                    }
                    return opcodes[id].length;
                }
            }
        }
    }
    assert(!"invalid op/mode");
}

int translate_program(const char *program, unsigned char *bytes, int size, int base_address)
{
    // do 2 passes:
    // 1) index labels
    // 2) actually do translation
    int offset = 0;
    for (int pass = 0; pass < 2; pass++)
    {
        const char *c = program;
        const char *end = program + size - 1;
        const char *line = c;
        parsed_line parsed;
        int length = 0;
        offset = base_address;
        while (c <= end)
        {
            if ((*c == '\n') || (*c == '\r') || (*c == 0) || (c == end))
            {
                if (length > 0)
                {
                    parse_line(line, length, &parsed);
                    if (strlen(parsed.label) > 0)
                    {
                        if (pass == 0)
                        {
                            labels = add_symbol(labels, parsed.label, offset);
                        }
                    }
                    if (_stricmp(parsed.op, "DEFINE") == 0)
                    {
                        if (pass == 0)
                        {
                            // special case, split symbol and value
                            int pos = 0;
                            int len = strlen(parsed.args);
                            for (int i = 0; i < len; i++)
                            {
                                if ((parsed.args[i] == ' ') || (parsed.args[i] == '\t'))
                                {
                                    pos = i;
                                    break;
                                }
                            }
                            parsed.args[pos] = 0;
                            pos++;
                            while ((parsed.args[pos] == ' ') || (parsed.args[pos] == '\t'))
                            {
                                pos++;
                            }
                            int value = parse_value(parsed.args + pos);
                            defines = add_symbol(defines, parsed.args, value);
                        }
                    }
                    else if (parsed.op[0])
                    {
                        if (_stricmp(parsed.op, "DCB") == 0)
                        {
                            // TODO: implement
                            offset += translate_dcb(parsed.args, bytes + offset);
                        }
                        else if (parsed.op[0] == '*')
                        {
                            offset = parse_value(parsed.args);
                        }
                        else
                        {
                            int address = 0;
                            address_mode mode = get_address_mode(parsed.args, &address);
                            offset += translate_instruction(parsed.op, mode, offset, address, bytes + offset);
                        }
                    }
                }
                if (*c == 0)
                {
                    break;
                }
                line = c + 1;
                length = 0;
            }
            else
            {
                length++;
            }
            c++;
        }
    }
    return offset - base_address;
}

int asm_program(const char *program, unsigned char *bytes, int size, int base_address)
{
    int byte_size = translate_program(program, bytes, size, base_address);
#if 0
    printf("\nDEFINES\n=======\n");
    print_symbols(defines);
    printf("\nLABELS\n=======\n");
    print_symbols(labels);
#endif
    return byte_size;
}

void asm_test()
{
#if 1
    const char *program =
        "; static noise\n"
        "\n"
        "define symbol 123\n"
        "start: ldy #$ff\n\r"
        "       ldx\t#$0\n"
        "loop:  lda $fe\n"
        "   \t    sta $200  ,  x\n"
        "       and #$7\n"
        "define another $123\n"
        "       sta $300, x\r"
        "       and #$3\n"
        "       sta $400 ,x\n"
        "      and   #$1\n"
        "       sta $500,x\n"
        "       inx\n"
        "       dey\n"
        "       bne loop\n"
        "       rts\n"
        "*=512\n"
        "offset512:"
        "*=$400\n"
        "offsetx400:"
        //"label: dcb 12,34,56"
        ;
#else
    const char *program =
        "XXX #$FFFF\n"
        "XXX #9999\n"
        "XXX #<label\n"
        "XXX #>label\n"
        "XXX #symbol\n"
        "XXX $FFFF\n"
        "XXX $0,x \n"
        "XXX $FFFF ,x\n"
        "XXX $FFFF,y\n"
        "XXX ($0 ),y\n"
        "XXX ($0,x)\n"
        "XXX (label ) , y\n"
        "XXX (label , x)\n"
        "XXX 9999\n"
        "XXX label\n"
        "XXX label,x\n"
        "XXX label,y\n"
        "XXX a\n";

#endif
    unsigned char *bytes = (unsigned char *)malloc(0x10000);
    int size = asm_program(program, bytes, sizeof(program) - 1, 0x600);
    disasm_program(bytes, size, 0x600, stdout);
}

int main(int argc, char *argv[])
{
    bool disasm = false;
    int base_address = 0x600;

    init();

    int out_buffer_size = 0x10000;
    unsigned char *out_data = (unsigned char *)malloc(out_buffer_size);

    for (int i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-' && argv[i][1] == 'd')
        {
            disasm = true;
        }
        else if (argv[i][0] == '-' && argv[i][1] == 'b')
        {
            base_address = parse_value(&argv[i][2]);
        }
        else
        {
            FILE *f_in;
            fopen_s(&f_in, argv[i], "rb");
            
            if (f_in)
            {
                printf("Processing file: %s\n", argv[i]);
                free_symbols(&labels);
                free_symbols(&defines);
                assert(labels == 0);
                assert(defines == 0);

                fseek(f_in, 0, SEEK_END);
                int input_size = ftell(f_in);
                unsigned char *input_data = (unsigned char *)malloc(input_size);

                fseek(f_in, 0, SEEK_SET);
                fread((void *)input_data, input_size, 1, f_in);
                fclose(f_in);

                if (!disasm)
                {
                    memset(out_data, 0, out_buffer_size);
                    int out_size = asm_program((const char *)input_data, out_data, input_size, base_address);

                    FILE *f_out;
                    char outname[100] = "../disasm/";
                    strcat_s(outname, argv[i]);
                    int len = strnlen_s(outname, sizeof(outname));
                    outname[len - 3] = 0;
                    strcat_s(outname, "disasm");

                    printf("Writing to file: %s\n", outname);
                    fopen_s(&f_out, outname, "wb");
                    if (f_out)
                    {
                        disasm_program(out_data, out_size, base_address, f_out);
                        fclose(f_out);
                    }
                    else
                    {
                        printf("Error opening output file: %s\n", outname);
                    }
                }
                else
                {
                    disasm_program(input_data, input_size, base_address, stdout);
                }

                free(input_data);
            }
            else
            {
                printf("Error opening input file: %s\n", argv[i]);
            }
        }
    }

    system("pause");
    return 0;
}