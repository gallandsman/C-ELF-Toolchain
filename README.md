 C-ELF Toolchain: Low-Level System Utilities

## 📘 Project Overview

This is a set of **Low-Level C programs** built to understand and manipulate the core file structure of executables (ELF).
The project focuses on two key OS concepts: analyzing the binary structure (`myELF.c`) and implementing a static program loader (`loader.c`) that directly manages memory.

## 🧩 Components & Features

1.  **myELF.c (Analyzer & Linker)**
    * **Binary Analysis:** Uses the **mmap** system call to read and display key structures: ELF Headers, Section Headers, and Symbol Tables.
    * **Linking:** Implemented a limited **Linker Pass I** (ld -r functionality) to check symbol definitions and physically **merge sections** (`.text`, `.data`, `.rodata`) from two input files.
    
2.  **loader.c (Static Program Loader)**
    * **Memory Management:** Implements the program loader by dynamically mapping `PT_LOAD` segments from the ELF file into **Virtual Memory**.
    * **Low-Level Control:** Handles segment alignment, sets correct memory **Protection Flags** (R/W/X), and transfers control to the loaded code's entry point via **Assembly glue code**.
  
## ⚙️ Running & Building Instructions
* This section details how to build and execute the C-ELF Toolchain utilities on a Linux/Unix 32-bit environment.
* The project requires **GCC** (with the `-m32` flag) and **NASM** for the Assembly code.
* To build, first assemble the glue code: `nasm -f elf start.s -o start.o` and `nasm -f elf startup.s -o startup.o`. 
* Next, compile and link the `loader` using the custom linker script: `gcc -g -m32 loader.c start.o startup.o -o loader -T linking_script`.
* Separately, compile the analyzer: `gcc -g -m32 myELF.c -o myELF`. 
* The built executables are ready to run against the provided test files: The **Static Program Loader** runs with `./loader loadme [OPTIONAL_ARGS]`,
* The **ELF Analyzer** is run via a menu with `./myELF` (where you can load and merge test object files like **`F1a.o`** and **`F2a.o`**).
