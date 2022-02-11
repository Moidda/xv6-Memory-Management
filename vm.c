#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"

// added
#define FIFO      0
#define AGING     1
#define BUFSIZE   (PGSIZE/4)


extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()

// added
void printva(struct proc* curproc) {
  int i;
  cprintf("Pages in file:\n");
  for(i = 0; i < curproc->nMemPages; i++) 
    cprintf("\tva[%d] = %d\tva_swap[%d] = %d\n", i, (uint) curproc->va[i], i, (uint) curproc->va_swap[i]);
}

// added
int getFifo(struct proc* curproc) {
  int i;
  if(curproc->nMemPages == 0) 
    panic("getFifo error: No pages in memory to swap out\n");
  return 0;
}

// added
char* getAging(struct proc* curproc) {
  return 0;
}

// added
int getPage(struct proc *curproc, int page_replacement_algo) {
  if(page_replacement_algo == FIFO) return getFifo(curproc);
  if(page_replacement_algo == AGING) return getAging(curproc);
  return 0;
}

// added
void shiftLeft(struct proc *curproc, int idx) {
  int i;
  for(i = idx; i+1<MAX_PSYC_PAGES; i++) 
    curproc->va[i] = curproc->va[i+1];
}


// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
 { (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
 { (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
 { (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
 { (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if((pgdir = (pde_t*)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void*)DEVSPACE)
    panic("PHYSTOP too high");
  for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if(mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                (uint)k->phys_start, k->perm) < 0) {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
  kpgdir = setupkvm();
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
  lcr3(V2P(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
  if(p == 0)
    panic("switchuvm: no process");
  if(p->kstack == 0)
    panic("switchuvm: no kstack");
  if(p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
                                sizeof(mycpu()->ts)-1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort) 0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->pgdir));  // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W|PTE_U);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if((uint) addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, P2V(pa), offset+i, n) != n)
      return -1;
  }
  return 0;
}

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  // cprintf("------------- Inside allocuvm -------------\n");

  char *mem;
  uint a;

  if(newsz >= KERNBASE)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  for(; a < newsz; a += PGSIZE){
    mem = kalloc();                                  // get a virtual address space
    struct proc *curproc = myproc();
    int page_no = curproc->nMemPages + curproc->nFilePages + 1;

    cprintf("\tAssigning page no: %d, va = %d\n", page_no, a);

    if(page_no <= MAX_PSYC_PAGES) {
      curproc->nMemPages = page_no; 
      curproc->va[page_no-1] = (char*)a;
      cprintf("\tcurproc->va[%d] = %d\n", page_no-1, curproc->va[page_no-1]);
    }
    else {
      pte_t* pte;
      int file_offset = curproc->nFilePages*PGSIZE;
      int va_idx = getPage(curproc, FIFO);
      char* va_0 = curproc->va[va_idx];
      shiftLeft(curproc, va_idx);

      cprintf("\tAlgo chose to swap out va[%d] = %d\n", va_idx, va_0);

      if( (pte = walkpgdir(pgdir, (void*)va_0, 0)) == 0)
        panic("Swap Error: No pte found against va returned by algo");

      uint pa = PTE_ADDR(*pte);
      char *v = P2V(pa);
      if(pa == 0) 
        panic("Swap Error: No physical address found by va returned by algo");

      if(writeToSwapFile(curproc, v, file_offset, PGSIZE) == -1) {
        cprintf("Panic follows: In process pid:%d, name:%s\n", curproc->pid, curproc->name);
        panic("Error writing to swap file");
      }
      cprintf("\tWritten to swap file\n");

      kfree(v);
      *pte = (PTE_W | PTE_U | PTE_PG);

      lcr3(V2P(curproc->pgdir));

      // populate metadata
      curproc->va_swap[curproc->nFilePages] = (char*)va_0;  // va_0 is now stored in swap 
      curproc->nFilePages++;                                // increment #total pages
      curproc->va[MAX_PSYC_PAGES-1] = (char*)a;             // assign new va to newly created empty space
    
      printva(curproc);
    }
    // end

    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0){
      cprintf("allocuvm out of memory (2)\n");
      deallocuvm(pgdir, newsz, oldsz);
      kfree(mem);
      return 0;
    }
  }
  // cprintf("------------- End allocuvm -------------\n");
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for(; a  < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte)
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
      
      // added
      if(myproc()->pgdir == pgdir)
        myproc()->nMemPages--;
    }
  }
  return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void
freevm(pde_t *pgdir)
{
  uint i;

  if(pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for(i = 0; i < NPDENTRIES; i++){
    if(pgdir[i] & PTE_P){
      char * v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char*)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if(pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  if((d = setupkvm()) == 0)
    return 0;
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
      panic("copyuvm: pte should exist");
    if(!(*pte & PTE_P))
      panic("copyuvm: page not present");
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, (char*)P2V(pa), PGSIZE);
    if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags) < 0) {
      kfree(mem);
      goto bad;
    }
  }
  return d;

bad:
  freevm(d);
  return 0;
}

//PAGEBREAK!
// Map user virtual address to kernel address.
char*
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if((*pte & PTE_P) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  return (char*)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char*)p;
  while(len > 0){
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char*)va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if(n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}


// added
pte_t* getWalkpgdir(pde_t *pgdir, const void *va) {
  return walkpgdir(pgdir, va, 0);
}

// added
void swapPageIn(struct proc* curproc, char* va) {
  cprintf("------------ In Swap Page ------------\n");

  int i = 0, va1_i, va2_i;
  pte_t *pte_1, *pte_2;
  char buf[BUFSIZE];
  
  for(va2_i = 0; va2_i < curproc->nFilePages; va2_i++) 
    if(curproc->va_swap[va2_i] == va)
      break;

  if(va2_i == curproc->nFilePages) 
    panic("SwapPageIn: va not found\n");

  int location_in_file = va2_i*PGSIZE;
  int offset = 0;
  va1_i = getPage(curproc, FIFO);
  char* va_0 = curproc->va[va1_i];

  char *mem = kalloc();
  if(mem == 0) 
    panic("SwapPageIn:allocuvm out of memory\n");

  memset(mem, 0, PGSIZE);
  if(mappages(curproc->pgdir, va, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0) {
    cprintf("SwapPageIn:allocuvm out of memory for mapapges\n");
    kfree(mem);
  }

  if( (pte_1 = walkpgdir(curproc->pgdir, (void*)va_0, 0)) == 0) 
    panic("Swap Page IN Error: No pte found against va returned by algo\n");

  if( (pte_2 = walkpgdir(curproc->pgdir, (void*)va, 0)) == 0) 
    panic("Swap Page IN Error: No pte found against page fault address\n");

  uint pa1 = PTE_ADDR(*pte_1);
  uint pa2 = PTE_ADDR(*pte_2);

  readFromSwapFile(curproc, (char*)P2V(pa2), va2_i*PGSIZE, PGSIZE);
  writeToSwapFile(curproc, (char*)P2V(pa1), va2_i*PGSIZE, PGSIZE);

  kfree((char*)P2V(pa1));
  *pte_1 = (PTE_W | PTE_U | PTE_PG);    // pte_1 has been paged out
  *pte_2 &= (~PTE_PG);                   
  
  lcr3(V2P(curproc->pgdir));

  shiftLeft(curproc, va1_i);                // move all elements of curproc->va to 1 step left
  curproc->va_swap[va2_i] = (char*) va_0;   // va_0 is now stored in swap file, substituting va
  curproc->va[MAX_PSYC_PAGES-1] = va;       // va is now stored at the tail of list
  curproc->pageFault++;

  cprintf("------------ End Swap Page ------------\n");
}




//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.

