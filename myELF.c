#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>      
#include <unistd.h>     
#include <sys/mman.h>   
#include <sys/stat.h>   
#include <elf.h> 

#define MAX_FILES 2

int fds[MAX_FILES];
void* map_starts[MAX_FILES];
char file_names[MAX_FILES][100];
off_t file_size[MAX_FILES];
int file_count = 0;
char debug_mode = 0; 

/* -------------------------------------------------- auxilery functions-------------------------------------------------------------------------*/
void print_ehdr(Elf32_Ehdr* ehdr){
    printf("\n");
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", (unsigned char)ehdr->e_ident[i]);
    }
    printf("\n");

    printf("  Data:                              ");
    switch (ehdr->e_ident[EI_DATA]) {
        case ELFDATA2LSB:
            printf("2's complement, little endian\n");
            break;
        case ELFDATA2MSB:
            printf("2's complement, big endian\n");
            break;
        default:
            printf("Invalid data encoding\n");
    }

    printf("  Entry point address:               0x%x\n", ehdr->e_entry);
    printf("  Start of section headers:          %u (bytes into file)\n", ehdr->e_shoff);
    printf("  Number of section headers:         %u\n", ehdr->e_shnum);
    printf("  Size of section headers:           %u (bytes)\n", ehdr->e_shentsize);
    printf("  Start of program headers:          %u (bytes into file)\n", ehdr->e_phoff);
    printf("  Number of program headers:         %u\n", ehdr->e_phnum);
    printf("  Size of program headers:           %u (bytes)\n", ehdr->e_phentsize);
}

const char* section_type_to_string(uint32_t type) {
    switch (type) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_STRTAB: return "STRTAB";
        case SHT_RELA: return "RELA";
        case SHT_HASH: return "HASH";
        case SHT_DYNAMIC: return "DYNAMIC";
        case SHT_NOTE: return "NOTE";
        case SHT_NOBITS: return "NOBITS";
        case SHT_REL: return "REL";
        case SHT_SHLIB: return "SHLIB";
        case SHT_DYNSYM: return "DYNSYM";
        default: return "UNKNOWN";
    }
}

// Returns the section name corresponding to the given section index (shndx) using the section header table and section name string table.
const char* get_section_name(Elf32_Ehdr* ehdr, Elf32_Shdr* shdr_table, const char* shstrtab, uint16_t shndx) {
    if (shndx == SHN_UNDEF)
        return "UND";
    else if (shndx == SHN_ABS)
        return "ABS";
    else if (shndx == SHN_COMMON)
        return "COM";
    else if (shndx < ehdr->e_shnum)
        return shstrtab + shdr_table[shndx].sh_name;
    else
        return "INVALID";
}

static size_t pad_to_align(FILE *fd, size_t offset, size_t align) {
    if (align == 0) return offset;
    size_t rem = offset % align;
    size_t pad = rem ? (align - rem) : 0;
    if (pad) {
        char *zeros = calloc(1, pad);
        fwrite(zeros, 1, pad, fd);
        free(zeros);
    }
    return offset + pad;
}

/* ------------------------------------------------------auxilery functions---------------------------------------------------------------------*/


void toggle_debug_mode() {
    debug_mode = !debug_mode;
    fprintf(stderr, "Debug flag now %s\n", debug_mode ? "on" : "off");
}

void examine_elf_file() {

    if (file_count == MAX_FILES){
        printf("can't handle more than 2 files");
        printf("\n");
        return;
    }

    printf("Enter ELF file name: ");
    if (scanf("%99s", file_names[file_count]) != 1) {
        printf("Failed to read file name\n");
        return;
    }

    fds[file_count] = open(file_names[file_count], O_RDONLY); //open the file
        if (fds[file_count] < 0) {
            perror("open file failed");   
            return;
        }
        
    file_size[file_count] = lseek(fds[file_count], 0, SEEK_END); // compute file size
        if (file_size[file_count] == -1) {
            perror("lseek failed");
                close(fds[file_count]);
                return;
        }
           
    // Map the file into memory: let the OS choose the address (NULL),
    // read-only access (PROT_READ), and private copy-on-write mapping (MAP_PRIVATE)
    map_starts[file_count] = mmap(NULL, file_size[file_count], PROT_READ, MAP_PRIVATE, fds[file_count], 0);
        if (map_starts[file_count] == MAP_FAILED) {
            perror("mmap failed");
                close(fds[file_count]);
                return;
        }

    Elf32_Ehdr* ehdr = (Elf32_Ehdr*) map_starts[file_count];
    print_ehdr(ehdr);
    file_count++;
}

void print_section_names() {
    if (file_count == 0){
        printf("no open files");
        return;
        }
    // loop over all loaded ELF files
    for (int i = 0; i < file_count; i++) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*) map_starts[i]; // pointer to the ELF header at the start of the mapped file
        Elf32_Shdr* shdr_table = (Elf32_Shdr*)((char*)map_starts[i] + ehdr->e_shoff);  //  pointer to the section header table using offset from ELF header
        Elf32_Shdr shstrtab_header = shdr_table[ehdr->e_shstrndx]; // section header that contains the section names (shstrtab section)
        const char* shstrtab = (char*)map_starts[i] + shstrtab_header.sh_offset; //  pointer to the section name string table itself (to get names by offset)
    
        printf("\n");
        printf("file: %s\n", file_names[i]);
        if (debug_mode) {
            fprintf(stderr, "e_shoff = %u\n", ehdr->e_shoff);  // offset in the file where the section header table starts
            fprintf(stderr, "e_shnum = %u\n", ehdr->e_shnum);  // number of section headers in the table
            fprintf(stderr, "e_shstrndx = %u\n", ehdr->e_shstrndx); // index in the section table that points to the section containing section names
            fprintf(stderr, "shstrtab offset = %u\n", shstrtab_header.sh_offset);  // offset inside the file to the actual section name string table
            printf("\n");
        }

        printf("[index]  name             address    offset    size    type\n");
   
        // loop through all section headers in the file
        for(int j = 0; j< ehdr->e_shnum; j++){
            Elf32_Shdr* sh = &shdr_table[j]; // pointer to the current section header
            const char* name = shstrtab + sh->sh_name; // get the section name from the section header string table
            printf("[%2d]   %-18s %08x   %06x   %06x   %s\n",
                   j, name, sh->sh_addr, sh->sh_offset, sh->sh_size, section_type_to_string(shdr_table[j].sh_type));       
        } 
    }
}

void print_symbols() {
    if (file_count == 0){
        printf("no open files");
        return;
        }
    for (int i = 0; i < file_count; i++) {

        Elf32_Ehdr* ehdr = (Elf32_Ehdr*) map_starts[i]; // get pointer to the ELF header at the start of the mapped file
        Elf32_Shdr* shdr_table = (Elf32_Shdr*)((char*)map_starts[i] + ehdr->e_shoff);  //  pointer to the section header table using offset from ELF header
        Elf32_Shdr shstrtab_header = shdr_table[ehdr->e_shstrndx]; //section header that contains the section names (shstrtab section)
        const char* shstrtab = (char*)map_starts[i] + shstrtab_header.sh_offset; //  pointer to the section name string table itself (to get names by offset)
    
        Elf32_Shdr* symtab_section = NULL;// pointer to the symbol table

       // loop over all section in the section table of the file to find the symbol table
       for (int j = 0; j < ehdr->e_shnum; j++) {
            Elf32_Shdr* sh = &shdr_table[j];
            if(sh->sh_type == SHT_SYMTAB) {
                symtab_section = sh;     
                break; 
            }
         }
        // if no symbols in current file move to the next one.
        if (symtab_section == NULL){ 
            printf("no symbolls in file: %s\n", file_names[i]);
            continue;
        }

        int symtab_size = symtab_section->sh_size; // size of table
        int num_symbols = symtab_size / symtab_section->sh_entsize;// number of symbols, symtab_section->sh_entsize  = size (in bytes) of each entry in the section.

        printf("\n");
        printf("file: %s\n", file_names[i]);

        if (debug_mode){
            printf("size of symbol table: %d\n", symtab_size);
            printf("number of symbols: %d\n", num_symbols);
            printf("\n");
        }

        // Pointer to the symbol table entries (array of Elf32_Sym)
        Elf32_Sym* symtab = (Elf32_Sym*)((char*)map_starts[i] + symtab_section->sh_offset);

        // Find the string table section for symbol names
        Elf32_Shdr* strtab_section = &shdr_table[symtab_section->sh_link];
        const char* strtab = (char*)map_starts[i] + strtab_section->sh_offset;

        printf("[index]  value   sec_index   sec_name         sym_name\n");

        for (int k = 0; k < num_symbols; k++) {
            Elf32_Sym* sym = &symtab[k];

            const char* section_name = get_section_name(ehdr, shdr_table, shstrtab, sym->st_shndx); //sym->st_shndx: section index where the symbol is defined
            const char* symbol_name = strtab + sym->st_name; // Get the symbol name by using the offset st_name into the string table (strtab)

            printf("[%2d]   %08x     %-10d %-15s %s\n", k, sym->st_value, sym->st_shndx, section_name, symbol_name);
        }
    }
}

void check_files_for_merge() {
    if (file_count != 2) {
        printf("less then 2 files are mapped\n");
        return;
    }

    for (int f = 0; f < 2; f++) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*) map_starts[f];
        Elf32_Shdr* shdr_table = (Elf32_Shdr*)((char*) map_starts[f] + ehdr->e_shoff);
        Elf32_Shdr* symtab_section = NULL;

        // Find symbol table
        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr_table[i].sh_type == SHT_SYMTAB) {
                if (symtab_section != NULL) { // more then 1 symbol table
                    printf("feature not supported\n");
                    return;
                }
                symtab_section = &shdr_table[i];
            }
        }

        if (symtab_section == NULL) {
            printf("feature not supported\n");
            return;
        }
    }

    // Get both symbol tables and string tables
    Elf32_Sym *symtabs[2];
    int symcounts[2];
    const char* strtabs[2];

    for (int f = 0; f < 2; f++) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*) map_starts[f]; // ELF header
        Elf32_Shdr* shdr_table = (Elf32_Shdr*)((char*) map_starts[f] + ehdr->e_shoff); // section header table

        Elf32_Shdr* symtab = NULL;
        // Find the symbol table section (SHT_SYMTAB) in section header table
        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr_table[i].sh_type == SHT_SYMTAB) {
                symtab = &shdr_table[i];
                break;
            }
        }

        symtabs[f] = (Elf32_Sym*)((char*) map_starts[f] + symtab->sh_offset); //symbol table pointer for each file
        symcounts[f] = symtab->sh_size / sizeof(Elf32_Sym);   // number of symbols in the table for each file
        Elf32_Shdr* strtab_section = &shdr_table[symtab->sh_link]; // string table section that contains the symbol names
        strtabs[f] = (const char*) map_starts[f] + strtab_section->sh_offset; // pointer to the string table
    }

    // Check symbols in each file
    for (int a = 0; a < 2; a++) {
        int b = 1 - a; // the other file
        for (int i = 1; i < symcounts[a]; i++) { // starts from 1 beacause o is dummy symbol
            Elf32_Sym* sym1 = &symtabs[a][i]; // symbol i from file a
            const char* name1 = strtabs[a] + sym1->st_name; // symbol name from string table

            // Skip symbols with empty name
            if (strlen(name1) == 0)
                continue;

            int found_in_b = 0;
            Elf32_Sym* sym2_match = NULL; // Pointer to matching symbol in file b, if found

            // Search for the same symbol name in file b
            for (int j = 1; j < symcounts[b]; j++) {
                Elf32_Sym* sym2 = &symtabs[b][j];
                const char* name2 = strtabs[b] + sym2->st_name;
                if (strcmp(name1, name2) == 0) {
                    found_in_b = 1;
                    sym2_match = sym2;
                    break;
                }
            }
            //SHN_UNDEF: value 0 - symbol is undefined.
            //sym1->st_shndx: section index where the symbol is defined
            int sym1_is_undef = (sym1->st_shndx == SHN_UNDEF); 
            int sym2_is_undef = (!found_in_b || (sym2_match->st_shndx == SHN_UNDEF));

            if (sym1_is_undef && sym2_is_undef) {
                printf("Symbol %s undefined\n", name1);
            } else if (!sym1_is_undef && found_in_b && sym2_match->st_shndx != SHN_UNDEF) {
                printf("Symbol %s multiply defined\n", name1);
            }
        }
    }
}

void merge_elf_files() {

    // file 1
    Elf32_Ehdr* ehdr1 = (Elf32_Ehdr*) map_starts[0]; // ELF header
    Elf32_Ehdr header_copy = *ehdr1; // make a local copy for modify 
    Elf32_Shdr* sh_table1 = (Elf32_Shdr*)((char*)map_starts[0] + ehdr1->e_shoff); //section header table 
    Elf32_Shdr shstrtab_header1 = sh_table1[ehdr1->e_shstrndx]; // string table
    const char* shstrtab1 = (char*)map_starts[0] + shstrtab_header1.sh_offset; //  pointer to the section name string table 

    // file 2
    Elf32_Ehdr* ehdr2 = (Elf32_Ehdr*) map_starts[1]; // ELF header
    Elf32_Shdr* sh_table2 = (Elf32_Shdr*)((char*)map_starts[1] + ehdr2->e_shoff); //section header table 
    Elf32_Shdr shstrtab_header2 = sh_table2[ehdr2->e_shstrndx]; // string table
    const char* shstrtab2 = (char*)map_starts[1] + shstrtab_header2.sh_offset; //  pointer to the section name string table 

    // create new binary file for read and write
    FILE* fd_elf = fopen("out.ro", "wb+"); 
    if(fd_elf == NULL){
        printf("error in create new file");
        return;
    }
    
    fwrite(&header_copy, sizeof(Elf32_Ehdr), 1, fd_elf); // write ELF header for the file
    long current_offset = sizeof(Elf32_Ehdr);
    int original_shstrndx = ehdr1->e_shstrndx;
    Elf32_Shdr* new_sh_table = malloc(sizeof(Elf32_Shdr) * ehdr1->e_shnum); // alocate size in memory for the section table of the new file - (size of section header X num of section headers)
    memcpy(new_sh_table, sh_table1, sizeof(Elf32_Shdr) * ehdr1->e_shnum); //copy the sh of first file to memory


    for (int i = 0; i < ehdr1->e_shnum; i++) {
        Elf32_Shdr* sh = &new_sh_table[i];

        // current_offset = pad_to_align(fd_elf, current_offset, sh->sh_addralign);
        // sh->sh_offset = current_offset;

        const char* section_name = shstrtab1 + sh->sh_name;
        Elf32_Shdr* sh1 = NULL;
        Elf32_Shdr* sh2 = NULL;

        if (strcmp(section_name, ".text") == 0 || strcmp(section_name, ".data") == 0 || strcmp(section_name, ".rodata") == 0) {
            if (strcmp(section_name, ".text") == 0){

                // Locate the .text section in file 1           
                for(int j = 0; j < ehdr1->e_shnum; j++){
                const char* name1 = shstrtab1 + sh_table1[j].sh_name;
                    if (strcmp(name1, ".text") == 0) {
                        sh1 = &sh_table1[j];
                        break;
                    }
                }

                // Locate the .text section in file 
                for (int k = 0; k < ehdr2->e_shnum; k++) {
                    const char* name2 = shstrtab2 + sh_table2[k].sh_name;
                    if (strcmp(name2, ".text") == 0) {
                        sh2 = &sh_table2[k];
                        break;
                    }
                }
            }

            if (strcmp(section_name, ".data") == 0){

                // Locate the .data section in file 1           
                for(int j = 0; j < ehdr1->e_shnum; j++){
                    const char* name1 = shstrtab1 + sh_table1[j].sh_name;
                    if (strcmp(name1, ".data") == 0) {
                        sh1 = &sh_table1[j];
                        break;
                    }
                }

                // Locate the .data section in file 
                for (int k = 0; k < ehdr2->e_shnum; k++) {
                const char* name2 = shstrtab2 + sh_table2[k].sh_name;
                    if (strcmp(name2, ".data") == 0) {
                        sh2 = &sh_table2[k];
                        break;
                    }
                }
            }
            if (strcmp(section_name, ".rodata") == 0){

                // Locate the .rodata section in file 1           
                for(int j = 0; j < ehdr1->e_shnum; j++){
                    const char* name1 = shstrtab1 + sh_table1[j].sh_name;
                    if (strcmp(name1, ".rodata") == 0) {
                        sh1 = &sh_table1[j];
                        break;
                    }
                }

                // Locate the .rodata section in file 
                for (int k = 0; k < ehdr2->e_shnum; k++) {
                    const char* name2 = shstrtab2 + sh_table2[k].sh_name;
                    if (strcmp(name2, ".rodata") == 0) {
                        sh2 = &sh_table2[k];
                        break;
                    }
                }
            }
        if (sh2 == NULL) {
            // Update offset
            sh->sh_offset = current_offset;

            // Write .section from file 1
            void* data1 = (char*)map_starts[0] + sh1->sh_offset;
            fwrite(data1, 1, sh1->sh_size, fd_elf);

            // Update size and current offset
            sh->sh_size = sh1->sh_size;
            current_offset += sh->sh_size;

        } else {
            // Update offset
            sh->sh_offset = current_offset;

            // Write .section from file 1
            void* data1 = (char*)map_starts[0] + sh1->sh_offset;
            fwrite(data1, 1, sh1->sh_size, fd_elf);

            // Write .section from file 2
            void* data2 = (char*)map_starts[1] + sh2->sh_offset;
            fwrite(data2, 1, sh2->sh_size, fd_elf);

            // Update size and current offset
            sh->sh_size = sh1->sh_size + sh2->sh_size;
            current_offset += sh->sh_size;
            }

        }

        else {
            Elf32_Shdr* sh1 = &sh_table1[i];

            // Update offset
            sh->sh_offset = current_offset;

            // Write .section from file 1
            void* data1 = (char*)map_starts[0] + sh1->sh_offset;
            fwrite(data1, 1, sh1->sh_size, fd_elf);

            // Update size and current offset
            sh->sh_size = sh1->sh_size;
            current_offset += sh->sh_size;
        }        
    }

    fwrite(new_sh_table, sizeof(Elf32_Shdr), ehdr1->e_shnum, fd_elf); // Write section header table at the end of the file
    header_copy.e_shoff = current_offset; // update ELF header to point to new section header table offset
    header_copy.e_shstrndx = original_shstrndx;
    fseek(fd_elf, 0, SEEK_SET); // go back to beginning of file to overwrite ELF header
    fwrite(&header_copy, sizeof(Elf32_Ehdr), 1, fd_elf); // write updated ELF header 

    fclose(fd_elf);
    free(new_sh_table);
}

void quit() {
    for (int i = 0; i < file_count; i++) {
        if (map_starts[i] != NULL) {
            munmap(map_starts[i], file_size[i]);
            close(fds[i]);
        }
    }
    file_count = 0;
    exit(0);
}

typedef struct {
    char *name;
    void (*func)();
} MenuOption;

MenuOption menu[] = {
    {"Toggle Debug Mode", toggle_debug_mode},
    {"Examine ELF File", examine_elf_file},
    {"Print Section Names", print_section_names},
    {"Print Symbols", print_symbols},
    {"Check Files for Merge", check_files_for_merge},
    {"Merge ELF Files", merge_elf_files},
    {"Quit", quit},
    {NULL, NULL}
};

int main() {
    int choice;
    while (1) {
        printf("\n");
        printf("Choose action:\n");
        for (int i = 0; menu[i].name != NULL; i++)
            printf("%d-%s\n", i, menu[i].name);
            printf("\n");

        printf("Option: ");
        if (scanf("%d", &choice) != 1) {
            break;
        }
        if (choice >= 0 && choice <= 6)
            menu[choice].func();
    }
    return 0;
}

