#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

enum address_mode
{
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

int disasm_single(unsigned char *bytes, int offset, int base_address)
{
    int id = bytes[offset];
    const char *mnemonic = opcodes[id].mnemonic;
    address_mode mode = opcodes[id].mode;

    unsigned int address = offset + base_address;
    unsigned int byte = bytes[offset + 1];
    unsigned int word = (bytes[offset + 2] << 8) | (bytes[offset + 1] & 0xff);
    unsigned int rel = offset + base_address + (signed char)byte;

    printf("%04X    ", address);

    if (opcodes[id].length == 3)
    {
        printf("%02X %02X %02X    ", bytes[offset], bytes[offset + 1], bytes[offset + 2]);
    }
    else if (opcodes[id].length == 2)
    {
        printf("%02X %02X       ", bytes[offset], bytes[offset + 1]);
    }
    else
    {
        printf("%02X          ", bytes[offset]);
    }

    switch (mode)
    {
        case address_mode_abs:
            printf("%s $%04X\n", mnemonic, word);
            break;
        case address_mode_abs_x:
            printf("%s $%04X,X\n", mnemonic, word);
            break;
        case address_mode_abs_y:
            printf("%s $%04X,Y\n", mnemonic, word);
            break;
        case address_mode_imp:            
            printf("%s\n", mnemonic);
            break;
        case address_mode_acc:
            printf("%s A\n", mnemonic);
            break;
        case address_mode_imm:
            printf("%s #$%02X\n", mnemonic, byte);
            break;
        case address_mode_ind:
            printf("%s ($%04X)\n", mnemonic, word);
            break;
        case address_mode_ind_x:
            printf("%s ($%02X,X)\n", mnemonic, byte);
            break;
        case address_mode_ind_y:
            printf("%s ($%02X),Y\n", mnemonic, byte);
            break;
        case address_mode_rel:
            printf("%s $%04X\n", mnemonic, rel);
            break;
        case address_mode_zp:
            printf("%s $%02X\n", mnemonic, byte);
            break;
        case address_mode_zp_x:
            printf("%s $%02X,X\n", mnemonic, byte);
            break;
        case address_mode_zp_y:
            printf("%s $%02X,Y\n", mnemonic, byte);
            break;
        default:
            assert(!"invalid code path");
            break;
    }

    return opcodes[id].length;
}

void disasm_program(unsigned char *bytes, int size, int base_address)
{
    for (int offset = 0; offset < size; )
    {
        offset += disasm_single(bytes, offset, 0x600);
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

    disasm_program(example, sizeof(example), 0x600);
}

/* label: mnemonic arg1, arg2 ; comment */

struct parsed_line
{
    char label[100];
    char op[100];
    char arg1[100];
    char arg2[100];
};

void parse_line(const char *line, int length, parsed_line *parsed)
{
    int pos = 0;
    int startToken = 0;
    int endToken = 0;
    bool inToken = false;

    parsed->label[0] = 0;
    parsed->op[0] = 0;
    parsed->arg1[0] = 0;
    parsed->arg2[0] = 0;

    while (pos < length)
    {
        bool label = false;

        if (line[pos] == ' ' || line[pos] == '\t')
        {
            if (inToken)
            {
                endToken = pos;
            }
            else
            {
                startToken = endToken = pos + 1;
            }
        }
        else if (line[pos] == ';') // comments
        {
            endToken = pos;
            pos = length; // ignore rest of line
        }
        else if (line[pos] == ':') // label
        {
            endToken = pos;
            label = true;
        }
        else if (line[pos] == ',') // split arguments
        {
            endToken = pos++;
        }
        else if (pos == length - 1) // reached end of line
        {
            endToken = pos + 1;
        }
        else if (!inToken)
        {
            startToken = pos;
            inToken = true;
        }

        pos++;

        int length = endToken - startToken;
        if (length > 0)
        {
            if (label && !parsed->label[0])
            {
                strncpy_s(parsed->label, sizeof(parsed->label), line + startToken, length);
                parsed->label[length] = 0;
            }
            else if (!parsed->op[0])
            {
                strncpy_s(parsed->op, sizeof(parsed->op), line + startToken, length);
                parsed->op[length] = 0;
            }
            else if (!parsed->arg1[0])
            {
                strncpy_s(parsed->arg1, sizeof(parsed->arg1), line + startToken, length);
                parsed->arg1[length] = 0;
            }
            else if (!parsed->arg2[0])
            {
                strncpy_s(parsed->arg2, sizeof(parsed->arg1), line + startToken, length);
                parsed->arg2[length] = 0;
            }
            else
            {
                assert(!"unexpected token");
            }

            startToken = endToken = pos;
            inToken = false;
        }
    }

    printf("L: %s   OP: %s   A1: %s   A2: %s\n", parsed->label, parsed->op, parsed->arg1, parsed->arg2);
}

void asm_program(const char *program)
{
    const char *c = program;
    const char *line = c;
    parsed_line parsed;
    int length = 0;
    while (*c)
    {
        if (*c == '\n' || *c == '\r')
        {
            if (length > 0)
            {
                parse_line(line, length, &parsed);
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
    parse_line(line, length, &parsed);
}

void asm_test()
{
    const char *program =
        "; static noise\n"
        "\n"
        "start: ldy #$ff\n\r"
        "       ldx\t#$0\n"
        "loop:  lda $fe\n"
        "   \t    sta $200  ,  x\n"
        "       and #$7\n"
        "       sta $300, x\r"
        "       and #$3\n"
        "       sta $400 ,x\n"
        "      and   #$1\n"
        "       sta $500,x\n"
        "       inx\n"
        "       dey\n"
        "       bne loop\n"
        "       rts";

    asm_program(program);
}

int main(int argc, char *argv[])
{
    init();

    asm_test();

    system("pause");
    return 0;
}