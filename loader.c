#include <elf.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>

void startup(int argc, char** argv, void* entry_point);

int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int i), int arg){
    Elf32_Ehdr* ehdr = (Elf32_Ehdr*) map_start; // Casting map_start to ELF header to access its fields  
    Elf32_Off ph_offset = ehdr->e_phoff;   // offset of rogram Headers table
    Elf32_Half ph_num = ehdr->e_phnum;  // number of program headers 
    Elf32_Phdr* ph_table = (Elf32_Phdr*)((char*)map_start + ph_offset); // address of the Program Headers table 
    
    printf("Type   Offset   VirtAddr   PhysAddr  FileSiz   MemSiz  Flg  Align\n");
    
    // apply func on each program headers
    for ( int i = 0; i < ph_num; i++){
        func(&ph_table[i], arg);
    }

return 0;
}
const char* get_phdr_type_name(uint32_t type) {
    switch (type) {
        case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP: return "INTERP";
        case PT_NOTE: return "NOTE";
        case PT_PHDR: return "PHDR";
        default: return "UNKNOWN";
    }
}

// print funcation of task 0
void print_phdr0(Elf32_Phdr* phdr, int i) {
    printf("Program header number %d at address %p\n", i, (void*)phdr);
}

void print_phdr(Elf32_Phdr* phdr, int prot_flags, int map_flags){
    char flags[4];
    int j = 0;
    if (phdr->p_flags & PF_R) flags[j++] = 'R';
    if (phdr->p_flags & PF_W) flags[j++] = 'W';
    if (phdr->p_flags & PF_X) flags[j++] = 'X';
    flags[j] = '\0';  

    printf("%-5s ", get_phdr_type_name(phdr->p_type));  //entry type
    printf("0x%06x ", phdr->p_offset);   // file offset
    printf("0x%08x ", phdr->p_vaddr);    // virtual address
    printf("0x%08x ", phdr->p_paddr);    // physical address
    printf("0x%06x ", phdr->p_filesz);   // file size
    printf("0x%06x ", phdr->p_memsz);    // memory size
    printf("%-3s ", flags);              // entry flags
    printf("0x%x\n", phdr->p_align);     // memory/file alignment

    if (phdr->p_type == PT_LOAD) {
        printf("----Protection flags: %d\n", prot_flags);
        printf("----Mapping flags: %d\n", map_flags);
        printf("\n");
    }
}

// Loads a LOAD segment into memory using mmap 
void load_phdr(Elf32_Phdr *phdr, int fd){
    if (phdr->p_type == PT_LOAD) {
        // Translate ELF segment flags to mmap protection flags
        int prot_flags = 0;
        if (phdr->p_flags & PF_R) prot_flags |= PROT_READ;
        if (phdr->p_flags & PF_W) prot_flags |= PROT_WRITE;
        if (phdr->p_flags & PF_X) prot_flags |= PROT_EXEC;
    
        // Set mmap mapping flags
        // MAP_FIXED: map at the exact virtual address from the ELF
        // MAP_PRIVATE: create a private copy in memory (don't modify the file)
        int map_flags = MAP_FIXED | MAP_PRIVATE;
    
        // Align file offset and memory address to 4096-byte memory blocks (mmap requires alignment)
        size_t page_size = 4096;  // size of a memory block
        size_t offset_aligned = phdr->p_offset & ~(page_size - 1); // round file offset down to block boundary
        size_t addr_aligned = (size_t)phdr->p_vaddr & ~(page_size - 1); // round memory address down to block boundary
        size_t diff = phdr->p_offset - offset_aligned; // distance from aligned offset to real offset
        size_t map_size = phdr->p_memsz + diff; // total size to map, including extra for alignment


        void* map = mmap((void*)addr_aligned, map_size, prot_flags, map_flags, fd, offset_aligned);
        if (map == MAP_FAILED) {
            perror("mmap failed");
            return;
        }

        print_phdr(phdr, prot_flags, map_flags);
    }
}

int main(int argc, char **argv) {
    int fd;
    off_t file_size;
    void* map_start;
    if (argc >= 2){
        fd = open(argv[1], O_RDONLY); //open the file
        if (fd < 0) {
            perror("open file failed");   
            return 1;
        }
        
        file_size = lseek(fd, 0, SEEK_END); // compute file size
        if (file_size == -1) {
                perror("lseek failed");
                close(fd);
                return 1;
            }
           
        // Map the file into memory: let the OS choose the address (NULL),
        // read-only access (PROT_READ), and private copy-on-write mapping (MAP_PRIVATE)
        map_start = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map_start == MAP_FAILED) {
                perror("mmap failed");
                close(fd);
                return 1;
        }

        foreach_phdr (map_start, load_phdr, fd);
        
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*) map_start;
        Elf32_Addr entry = ehdr->e_entry;

        // Prepare arguments for loaded program:
        int new_argc = argc - 2;
        char** new_argv = &argv[2];
        startup(new_argc, new_argv , (void*)entry);

        munmap(map_start, file_size); // clean up
        close(fd);
    }
    
    return 0;
}