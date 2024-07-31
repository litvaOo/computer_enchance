#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MOV_OPCODE 0b100010

int main(int argc, char *argv[]) {
  if (argc < 2) {
    puts("No input file");
    return EXIT_FAILURE;
  }
  FILE *program = fopen(argv[1], "r");
  if (program == NULL) {
    perror("Failed to open a file to read");
    return EXIT_FAILURE;
  }
  size_t disassemble_filename_length = strlen(argv[1]) + 3 * sizeof(char);
  char *disassemble_filename = malloc(disassemble_filename_length);
  strncpy(disassemble_filename, argv[1], disassemble_filename_length);
  strncat(disassemble_filename, ".asm", disassemble_filename_length);
  FILE *disassemble = fopen(disassemble_filename, "w");
  if (disassemble == NULL) {
    perror("Failed to open a file to write");
    return EXIT_FAILURE;
  }

  uint8_t instruction[6];
  char *w[2][8] = {{"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"},
                   {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"}};
  char *mods[8] = {"bx + si", "bx + di", "bp + si", "bp + di",
                   "si",      "di",      "bp",      "bx"};
  fread(instruction, 1, 1, program);
  while (feof(program) == 0) {
    if (ferror(program) != 0) {
      perror("Failed to read byte");
      return EXIT_FAILURE;
    }
    if (instruction[0] >> 2 == 0b100010) { // register/memory to/from register
      fread(&instruction[1], 1, 1, program);
      int mod = instruction[1] >> 6;
      int reg = (instruction[1] & 0b00111111) >> 3;
      int rm = instruction[1] & 0b00000111;
      char *reg_name = w[instruction[0] & 1][reg];
      char *rm_name = w[instruction[0] & 1][rm];
      char effective_address[8];
      strncpy(effective_address, mods[rm], 8);
      if (mod == 0b11) {
        if ((instruction[0] >> 1 & 1)) {
          fprintf(disassemble, "mov %s, %s\n", reg_name, rm_name);
        } else {
          fprintf(disassemble, "mov %s, %s\n", rm_name, reg_name);
        }
      } else if (mod == 0b00) {
        if (rm == 0b110) {
          fread(&instruction[2], 1, 2, program);
          sprintf(effective_address, "%d",
                  instruction[2] | instruction[3] << 8);
        }
        if ((instruction[0] >> 1 & 1))
          fprintf(disassemble, "mov %s, [%s]\n", reg_name, effective_address);
        else
          fprintf(disassemble, "mov [%s], %s\n", effective_address, reg_name);

      } else if (mod == 0b01) {
        fread(&instruction[2], 1, 1, program);
        uint8_t displacement = instruction[2];
        if ((instruction[0] >> 1 & 1)) {
          if (displacement != 0)
            fprintf(disassemble, "mov %s, [%s + %d]\n", reg_name,
                    effective_address, instruction[2]);
          else
            fprintf(disassemble, "mov %s, [%s]\n", reg_name, effective_address);
        } else {
          if (displacement != 0)
            fprintf(disassemble, "mov [%s + %d], %s\n", effective_address,
                    instruction[2], reg_name);
          else
            fprintf(disassemble, "mov [%s], %s\n", effective_address, reg_name);
        }
      } else if (mod == 0b10) {
        fread(&instruction[2], 1, 2, program);
        if ((instruction[0] >> 1 & 1))
          fprintf(disassemble, "mov %s, [%s + %d]\n", reg_name,
                  effective_address, instruction[2] | instruction[3] << 8);
        else
          fprintf(disassemble, "mov [%s + %d], %s\n", effective_address,
                  instruction[2] | instruction[3] << 8, reg_name);
      }
    } else if (instruction[0] >> 1 ==
               0b1100011) { // Immediate to register/memory
      size_t next_read = 4 + (instruction[0] & 1);
      fread(&instruction[1], 1, next_read, program);
      // TODO: implement
    } else if (instruction[0] >> 4 == 0b1011) { // immediate to register
      uint8_t width = ((instruction[0] >> 3) & 1);
      size_t next_read = 1 + width;
      fread(&instruction[1], 1, next_read, program);
      char *reg = w[width][(instruction[0] & 0b00000111)];
      uint16_t data = instruction[1];
      if (width) {
        data |= (instruction[2] << 8);
      }
      fprintf(disassemble, "mov %s, %d\n", reg, data);
    } else if (instruction[0] >> 2 == 0b101000) {
      size_t next_read = 1 + (instruction[0] & 1);
      fread(&instruction[1], 1, next_read, program);
      uint16_t address = instruction[1];
      if (instruction[0] & 1) {
        address |= instruction[2] << 8;
      }
      if (instruction[0] >> 1 & 1)
        fprintf(disassemble, "mov [%d], ax\n", address);
      else
        fprintf(disassemble, "mov ax, [%d]\n", address);
    } else {
      printf("Illegal Instruction %b\n", instruction[0]);
      // return EXIT_FAILURE;
    }

    fread(instruction, 1, 1, program);
  }
  return EXIT_SUCCESS;
}
