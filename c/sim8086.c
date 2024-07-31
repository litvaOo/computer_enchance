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
  fread(instruction, 1, 1, program);
  while (feof(program) == 0) {
    if (ferror(program) != 0) {
      perror("Failed to read byte");
      return EXIT_FAILURE;
    }
    if (instruction[0] >> 2 == 0b100010) { // register to register
      fread(&instruction[1], 1, 1, program);
      if ((instruction[1] >> 6 & 0b11) == 0b11) {
        char *reg;
        char *rm;

        reg = w[instruction[0] & 1][(instruction[1] & 0b00111111) >> 3];
        rm = w[instruction[0] & 1][instruction[1] & 0b00000111];
        if ((instruction[0] >> 1 & 1)) {
          fprintf(disassemble, "mov %s, %s\n", reg, rm);
        } else {
          fprintf(disassemble, "mov %s, %s\n", rm, reg);
        }
      } else {
        puts("Not handling that yet");
        // return EXIT_FAILURE;
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
      fprintf(disassemble, "mov %s %d\n", reg, data);
    } else {
      puts("ILLEGAL INSTRUCTION");
      return EXIT_FAILURE;
    }

    fread(instruction, 1, 1, program);
  }
  return EXIT_SUCCESS;
}
