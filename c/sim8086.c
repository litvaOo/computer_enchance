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
    fprintf(disassemble, "Instruction is %b\n", instruction[0]);
    if (instruction[0] >> 2 == 0b100011) { // register/memory to/from register
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
        int m = 1U << 7;
        int16_t displacement = (instruction[2] ^ m) - m;
        char *sign = "+";
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }
        if ((instruction[0] >> 1 & 1)) {
          if (displacement != 0)
            fprintf(disassemble, "mov %s, [%s %s %d]\n", reg_name,
                    effective_address, sign, displacement);
          else
            fprintf(disassemble, "mov %s, [%s]\n", reg_name, effective_address);
        } else {
          if (displacement != 0)
            fprintf(disassemble, "mov [%s %s %d], %s\n", effective_address,
                    sign, displacement, reg_name);
          else
            fprintf(disassemble, "mov [%s], %s\n", effective_address, reg_name);
        }
      } else if (mod == 0b10) {
        fread(&instruction[2], 1, 2, program);
        int16_t displacement = instruction[2] | instruction[3] << 8;
        char *sign = "+";
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }

        if ((instruction[0] >> 1 & 1))
          fprintf(disassemble, "mov %s, [%s %s %d]\n", reg_name,
                  effective_address, sign, displacement);
        else
          fprintf(disassemble, "mov [%s %s %d], %s\n", effective_address, sign,
                  displacement, reg_name);
      }
    } else if (instruction[0] >> 1 ==
               0b1100011) { // Immediate to register/memory
      fread(&instruction[1], 1, 1, program);
      size_t next_read = 1 + (instruction[0] & 1);
      int rm = instruction[1] & 0b00000111;
      char *rm_name = mods[rm];
      char *constant_size = instruction[0] & 1 ? "word" : "byte";
      int16_t immediate;
      int16_t displacement;
      char *sign = "+";
      if (instruction[1] >> 6 == 0b01) {
        next_read += 1;
        fread(&instruction[2], 1, next_read, program);
        int m = 1U << 7;
        displacement = (instruction[2] ^ m) - m;
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }
        immediate = instruction[3];
        if (instruction[0] & 1) {
          immediate |= instruction[4] << 8;
        }
      } else if (instruction[1] >> 6 == 0b10) {
        next_read += 2;
        fread(&instruction[2], 1, next_read, program);
        displacement = instruction[2] | instruction[3] << 8;
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }
        immediate = instruction[4];
        if (instruction[0] & 1) {
          immediate |= instruction[5] << 8;
        }
      } else if (instruction[1] >> 6 == 0b00) {
        fread(&instruction[2], 1, next_read, program);
        immediate = instruction[2];
        if (instruction[0] & 1) {
          immediate |= instruction[3] << 8;
        }
      }
      if (displacement == 0b00)
        fprintf(disassemble, "mov [%s], %s %d\n", rm_name, constant_size,
                immediate);
      else
        fprintf(disassemble, "mov [%s %s %d], %s %d\n", rm_name, sign,
                displacement, constant_size, immediate);
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
    } else if (instruction[0] >> 2 ==
               0b000000) { // ADD Reg/memory with register to either
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
          fprintf(disassemble, "add %s, %s\n", reg_name, rm_name);
        } else {
          fprintf(disassemble, "add %s, %s\n", rm_name, reg_name);
        }
      } else if (mod == 0b00) {
        if (rm == 0b110) {
          fread(&instruction[2], 1, 2, program);
          sprintf(effective_address, "%d",
                  instruction[2] | instruction[3] << 8);
        }
        if ((instruction[0] >> 1 & 1))
          fprintf(disassemble, "add %s, [%s]\n", reg_name, effective_address);
        else
          fprintf(disassemble, "add [%s], %s\n", effective_address, reg_name);

      } else if (mod == 0b01) {
        fread(&instruction[2], 1, 1, program);
        int m = 1U << 7;
        int16_t displacement = (instruction[2] ^ m) - m;
        char *sign = "+";
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }
        if ((instruction[0] >> 1 & 1)) {
          if (displacement != 0)
            fprintf(disassemble, "add %s, [%s %s %d]\n", reg_name,
                    effective_address, sign, displacement);
          else
            fprintf(disassemble, "add %s, [%s]\n", reg_name, effective_address);
        } else {
          if (displacement != 0)
            fprintf(disassemble, "add [%s %s %d], %s\n", effective_address,
                    sign, displacement, reg_name);
          else
            fprintf(disassemble, "add [%s], %s\n", effective_address, reg_name);
        }
      } else if (mod == 0b10) {
        fread(&instruction[2], 1, 2, program);
        int16_t displacement = instruction[2] | instruction[3] << 8;
        char *sign = "+";
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }

        if ((instruction[0] >> 1 & 1))
          fprintf(disassemble, "add %s, [%s %s %d]\n", reg_name,
                  effective_address, sign, displacement);
        else
          fprintf(disassemble, "add [%s %s %d], %s\n", effective_address, sign,
                  displacement, reg_name);
      }
    } else if (instruction[0] >> 2 ==
               0b100000) { // ADD/SBC/CMP Immediate to register/memory
      fread(&instruction[1], 1, 1, program);
      size_t next_read = 1 + (instruction[0] >> 6 == 0b01);
      int rm = instruction[1] & 0b00000111;
      int reg = (instruction[1] & 0b00111111) >> 3;
      char *rm_name = mods[rm];
      int16_t immediate;
      int16_t displacement = 0;
      char *command = "add";
      if (reg == 0b101) {
        command = "sub";
      }
      if (reg == 0b111) {
        command = "cmp";
      }
      char *sign = "+";
      if (instruction[1] >> 6 == 0b01) {
        next_read += 1;
        fread(&instruction[2], 1, next_read, program);
        int m = 1U << 7;
        displacement = (instruction[2] ^ m) - m;
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }
        immediate = instruction[3];
        if (instruction[0] >> 6 == 0b01) {
          immediate |= instruction[4] << 8;
        } else if (instruction[0] >> 6 == 0b11) {
          immediate = (instruction[3] ^ m) - m;
        }
      } else if (instruction[1] >> 6 == 0b10) {
        next_read += 2;
        fread(&instruction[2], 1, next_read, program);
        displacement = instruction[2] | instruction[3] << 8;
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }
        immediate = instruction[4];
        if (instruction[0] & 1) {
          immediate |= instruction[5] << 8;
        }
      } else if (instruction[1] >> 6 == 0b00) {
        fread(&instruction[2], 1, next_read, program);
        immediate = instruction[2];
        if (instruction[0] & 1) {
          immediate |= instruction[3] << 8;
        }
      } else if (instruction[1] >> 6 == 0b11) {
        rm_name = w[instruction[0] & 1][rm];
        next_read += (instruction[0] & 0b00000011) == 0b01;
        fread(&instruction[2], 1, next_read, program);
        immediate = instruction[2];
        if ((instruction[0] & 0b00000011) == 0b01) {
          immediate |= instruction[3];
        } else if ((instruction[0] & 0b00000011) == 0b11) {
          int m = 1U << 7;
          immediate = (instruction[2] ^ m) - m;
        }
      }
      if (displacement == 0b00)
        fprintf(disassemble, "%s [%s], %d\n", command, rm_name, immediate);
      else
        fprintf(disassemble, "%s [%s %s %d], %d\n", command, rm_name, sign,
                displacement, immediate);
    } else if (instruction[0] >> 1 ==
               0b0000010) { // ADD Immediate to accumulator
      uint8_t width = ((instruction[0] >> 3) & 1);
      size_t next_read = 1 + width;
      fread(&instruction[1], 1, next_read, program);
      char *reg = w[width][(instruction[0] & 0b00000111)];
      uint16_t data = instruction[1];
      if (width) {
        data |= (instruction[2] << 8);
      }
      fprintf(disassemble, "add %s, %d\n", reg, data);
    } else if (instruction[0] >> 2 == 0b101000) {
      size_t next_read = 1 + (instruction[0] & 1);
      fread(&instruction[1], 1, next_read, program);
      uint16_t address = instruction[1];
      if (instruction[0] & 1) {
        address |= instruction[2] << 8;
      }
      if (instruction[0] >> 1 & 1)
        fprintf(disassemble, "add [%d], ax\n", address);
      else
        fprintf(disassemble, "add ax, [%d]\n", address);
    } else if (instruction[0] >> 2 ==
               0b001010) { // SUB Reg/memory and register to either
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
          fprintf(disassemble, "sub %s, %s\n", reg_name, rm_name);
        } else {
          fprintf(disassemble, "sub %s, %s\n", rm_name, reg_name);
        }
      } else if (mod == 0b00) {
        if (rm == 0b110) {
          fread(&instruction[2], 1, 2, program);
          sprintf(effective_address, "%d",
                  instruction[2] | instruction[3] << 8);
        }
        if ((instruction[0] >> 1 & 1))
          fprintf(disassemble, "sub %s, [%s]\n", reg_name, effective_address);
        else
          fprintf(disassemble, "sub [%s], %s\n", effective_address, reg_name);

      } else if (mod == 0b01) {
        fread(&instruction[2], 1, 1, program);
        int m = 1U << 7;
        int16_t displacement = (instruction[2] ^ m) - m;
        char *sign = "+";
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }
        if ((instruction[0] >> 1 & 1)) {
          if (displacement != 0)
            fprintf(disassemble, "sub %s, [%s %s %d]\n", reg_name,
                    effective_address, sign, displacement);
          else
            fprintf(disassemble, "sub %s, [%s]\n", reg_name, effective_address);
        } else {
          if (displacement != 0)
            fprintf(disassemble, "sub [%s %s %d], %s\n", effective_address,
                    sign, displacement, reg_name);
          else
            fprintf(disassemble, "sub [%s], %s\n", effective_address, reg_name);
        }
      } else if (mod == 0b10) {
        fread(&instruction[2], 1, 2, program);
        int16_t displacement = instruction[2] | instruction[3] << 8;
        char *sign = "+";
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }

        if ((instruction[0] >> 1 & 1))
          fprintf(disassemble, "sub %s, [%s %s %d]\n", reg_name,
                  effective_address, sign, displacement);
        else
          fprintf(disassemble, "sub [%s %s %d], %s\n", effective_address, sign,
                  displacement, reg_name);
      }
    } else if (instruction[0] >> 1 ==
               0b0010110) { // SUB Immediate From accumulator
      uint8_t width = ((instruction[0] >> 3) & 1);
      size_t next_read = 1 + width;
      fread(&instruction[1], 1, next_read, program);
      char *reg = w[width][(instruction[0] & 0b00000111)];
      uint16_t data = instruction[1];
      if (width) {
        data |= (instruction[2] << 8);
      }
      fprintf(disassemble, "sub %s, %d\n", reg, data);
    } else if (instruction[0] >> 2 == 0b101000) {
      size_t next_read = 1 + (instruction[0] & 1);
      fread(&instruction[1], 1, next_read, program);
      uint16_t address = instruction[1];
      if (instruction[0] & 1) {
        address |= instruction[2] << 8;
      }
      if (instruction[0] >> 1 & 1)
        fprintf(disassemble, "sub [%d], ax\n", address);
      else
        fprintf(disassemble, "sub ax, [%d]\n", address);
    } else if (instruction[0] >> 2 == 0b001010) { // CMP Reg/memory and register
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
          fprintf(disassemble, "cmp %s, %s\n", reg_name, rm_name);
        } else {
          fprintf(disassemble, "cmp %s, %s\n", rm_name, reg_name);
        }
      } else if (mod == 0b00) {
        if (rm == 0b110) {
          fread(&instruction[2], 1, 2, program);
          sprintf(effective_address, "%d",
                  instruction[2] | instruction[3] << 8);
        }
        if ((instruction[0] >> 1 & 1))
          fprintf(disassemble, "cmp %s, [%s]\n", reg_name, effective_address);
        else
          fprintf(disassemble, "cmp [%s], %s\n", effective_address, reg_name);

      } else if (mod == 0b01) {
        fread(&instruction[2], 1, 1, program);
        int m = 1U << 7;
        int16_t displacement = (instruction[2] ^ m) - m;
        char *sign = "+";
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }
        if ((instruction[0] >> 1 & 1)) {
          if (displacement != 0)
            fprintf(disassemble, "cmp %s, [%s %s %d]\n", reg_name,
                    effective_address, sign, displacement);
          else
            fprintf(disassemble, "cmp %s, [%s]\n", reg_name, effective_address);
        } else {
          if (displacement != 0)
            fprintf(disassemble, "cmp [%s %s %d], %s\n", effective_address,
                    sign, displacement, reg_name);
          else
            fprintf(disassemble, "cmp [%s], %s\n", effective_address, reg_name);
        }
      } else if (mod == 0b10) {
        fread(&instruction[2], 1, 2, program);
        int16_t displacement = instruction[2] | instruction[3] << 8;
        char *sign = "+";
        if (displacement < 0) {
          displacement *= -1;
          sign = "-";
        }

        if ((instruction[0] >> 1 & 1))
          fprintf(disassemble, "cmp %s, [%s %s %d]\n", reg_name,
                  effective_address, sign, displacement);
        else
          fprintf(disassemble, "cmp [%s %s %d], %s\n", effective_address, sign,
                  displacement, reg_name);
      }
    } else if (instruction[0] >> 1 ==
               0b0010110) { // SUB Immediate From accumulator
      uint8_t width = ((instruction[0] >> 3) & 1);
      size_t next_read = 1 + width;
      fread(&instruction[1], 1, next_read, program);
      char *reg = w[width][(instruction[0] & 0b00000111)];
      uint16_t data = instruction[1];
      if (width) {
        data |= (instruction[2] << 8);
      }
      fprintf(disassemble, "sub %s, %d\n", reg, data);
    } else if (instruction[0] >> 2 == 0b101000) {
      size_t next_read = 1 + (instruction[0] & 1);
      fread(&instruction[1], 1, next_read, program);
      uint16_t address = instruction[1];
      if (instruction[0] & 1) {
        address |= instruction[2] << 8;
      }
      if (instruction[0] >> 1 & 1)
        fprintf(disassemble, "sub [%d], ax\n", address);
      else
        fprintf(disassemble, "sub ax, [%d]\n", address);
    } else if (instruction[0] >> 1 ==
               0b0010110) { // CMP Immediate and accumulator
      uint8_t width = ((instruction[0] >> 3) & 1);
      size_t next_read = 1 + width;
      fread(&instruction[1], 1, next_read, program);
      char *reg = w[width][(instruction[0] & 0b00000111)];
      uint16_t data = instruction[1];
      if (width) {
        data |= (instruction[2] << 8);
      }
      fprintf(disassemble, "cmp %s, %d\n", reg, data);
    } else if (instruction[0] >> 2 == 0b101000) {
      size_t next_read = 1 + (instruction[0] & 1);
      fread(&instruction[1], 1, next_read, program);
      uint16_t address = instruction[1];
      if (instruction[0] & 1) {
        address |= instruction[2] << 8;
      }
      if (instruction[0] >> 1 & 1)
        fprintf(disassemble, "cmp [%d], ax\n", address);
      else
        fprintf(disassemble, "cmp ax, [%d]\n", address);
    } else if (instruction[0] == 0b01110100) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "je %d\n", instruction[1]);
    } else if (instruction[0] == 0b01111100) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jl %d\n", instruction[1]);
    } else if (instruction[0] == 0b01111110) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jll %d\n", instruction[1]);
    } else if (instruction[0] == 0b01110010) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jb %d\n", instruction[1]);
    } else if (instruction[0] == 0b01110110) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jbe %d\n", instruction[1]);
    } else if (instruction[0] == 0b01111010) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jp %d\n", instruction[1]);
    } else if (instruction[0] == 0b01110000) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jo %d\n", instruction[1]);
    } else if (instruction[0] == 0b01111000) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "js %d\n", instruction[1]);
    } else if (instruction[0] == 0b01110101) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jne %d\n", instruction[1]);
    } else if (instruction[0] == 0b01111101) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jnl %d\n", instruction[1]);
    } else if (instruction[0] == 0b01111111) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jnle %d\n", instruction[1]);
    } else if (instruction[0] == 0b01110111) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jnbe %d\n", instruction[1]);
    } else if (instruction[0] == 0b01111011) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jnp %d\n", instruction[1]);
    } else if (instruction[0] == 0b01110001) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jno %d\n", instruction[1]);
    } else if (instruction[0] == 0b01111001) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jns %d\n", instruction[1]);
    } else if (instruction[0] == 0b11100010) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "loop %d\n", instruction[1]);
    } else if (instruction[0] == 0b11100001) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "loopz %d\n", instruction[1]);
    } else if (instruction[0] == 0b11100000) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "loopnz %d\n", instruction[1]);
    } else if (instruction[0] == 0b11100011) {
      fread(&instruction[1], 1, 1, program);
      fprintf(disassemble, "jcxz %d\n", instruction[1]);
    }

    else {
      printf("Illegal Instruction %b at offset %ld\n", instruction[0],
             ftell(program) - 1);
      // return EXIT_FAILURE;
    }
    fprintf(disassemble, "Current offset %ld \n\n", ftell(program) - 1);

    fread(instruction, 1, 1, program);
  }
  return EXIT_SUCCESS;
}
