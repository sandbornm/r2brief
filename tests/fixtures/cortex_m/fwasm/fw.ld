MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 64K
  RAM : ORIGIN = 0x20000000, LENGTH = 16K
}
ENTRY(Reset);
_stack_start = ORIGIN(RAM) + LENGTH(RAM);
SECTIONS
{
  .vector_table ORIGIN(FLASH) : { KEEP(*(.vector_table)); } > FLASH
  .text : { *(.text .text.*); } > FLASH
  .rodata : { *(.rodata .rodata.*); } > FLASH
  .data : { __sdata = .; *(.data .data.*); __edata = .; } > RAM AT > FLASH
  .bss (NOLOAD) : { __sbss = .; *(.bss .bss.*); __ebss = .; } > RAM
  /DISCARD/ : { *(.ARM.exidx .ARM.exidx.* .ARM.extab.*); }
}
