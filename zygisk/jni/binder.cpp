#include "binder.hpp"

#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "module.hpp"

bool getMapping(const char* lib_name, ino_t* inode, dev_t* dev) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char mapbuf[256], flags[8];
    int lib_name_len = strlen(lib_name);
    while (fgets(mapbuf, sizeof(mapbuf), fp)) {
        unsigned int dev_major, dev_minor;
        int cur = 0;
        sscanf(mapbuf, "%*s %s %*x %x:%x %lu %*s%n", flags, &dev_major, &dev_minor, inode, &cur);
        if (cur < lib_name_len) continue;
        if (memcmp(&mapbuf[cur - lib_name_len], lib_name, lib_name_len) == 0 && flags[2] == 'x') {
            *dev = makedev(dev_major, dev_minor);
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

uint32_t getStaticIntFieldJni(JNIEnv* env, const char* cls_name, const char* field_name) {
    jclass cls = env->FindClass(cls_name);
    if (cls == nullptr) {
        env->ExceptionClear();
        LOGD("ERROR getStaticIntFieldJni: Could not get class '%s'", cls_name);
        return 0;
    }
    jfieldID field = env->GetStaticFieldID(cls, field_name, "I");
    if (field == nullptr) {
        env->ExceptionClear();
        LOGD("ERROR getStaticIntFieldJni: Could not get field %s.%s", cls_name, field_name);
        return 0;
    }
    jint val = env->GetStaticIntField(cls, field);
    return val;
}

void companionSendFile(const char* path, int remote_fd) {
    off_t size = 0;
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        LOGD("ERROR open: %s", strerror(errno));
        goto defer;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        LOGD("ERROR fstat: %s", strerror(errno));
        goto defer;
    }
    size = st.st_size;

defer:
    if (write(remote_fd, &size, sizeof(size)) < 0) {
        LOGD("ERROR write: %s", strerror(errno));
        size = 0;
    }
    if (fd > 0) {
        if (size > 0 && sendfile(remote_fd, fd, NULL, size) < 0) {
            LOGD("ERROR sendfile: %s", strerror(errno));
        }
        close(fd);
    }
}

bool readFullFromFd(int fd, void* buf, off_t size) {
    off_t size_read = 0;
    while (size_read < size) {
        ssize_t ret = read(fd, (char*)buf + size_read, size - size_read);
        if (ret < 0) {
            LOGD("ERROR read: %s", strerror(errno));
            return false;
        } else {
            size_read += ret;
        }
    }
    return true;
}


// ---------------------------------------------------------------------------
static bool parseMapsLine(const char* line, unsigned long* s, unsigned long* e, char* perms, unsigned long* off,
                          unsigned* maj, unsigned* min, unsigned long* ino, const char** path) {
    int n = 0;
    if (sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %n", s, e, perms, off, maj, min, ino, &n) < 7 || n <= 0) return false;
    *path = line + n;
    return true;
}

bool findLibBase(const char* lib_name, uintptr_t* base, ino_t* inode, dev_t* dev, char* path_out, size_t path_sz) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[1024];
    size_t nlen = strlen(lib_name);
    bool found = false;
    unsigned long f_ino = 0;
    unsigned f_maj = 0, f_min = 0;
    // pass 1: first executable mapping whose path ends with /lib_name
    while (fgets(line, sizeof(line), fp)) {
        unsigned long s, e, off, ino;
        unsigned maj, min;
        char perms[8];
        const char* p;
        if (!parseMapsLine(line, &s, &e, perms, &off, &maj, &min, &ino, &p)) continue;
        size_t pl = strlen(p);
        while (pl && (p[pl - 1] == '\n' || p[pl - 1] == ' ')) pl--;
        if (pl < nlen + 1 || perms[2] != 'x') continue;
        if (memcmp(p + pl - nlen, lib_name, nlen) != 0 || p[pl - nlen - 1] != '/') continue;
        found = true;
        f_ino = ino;
        f_maj = maj;
        f_min = min;
        if (path_out && path_sz) {
            size_t cp = pl < path_sz - 1 ? pl : path_sz - 1;
            memcpy(path_out, p, cp);
            path_out[cp] = 0;
        }
        break;
    }
    if (!found) {
        fclose(fp);
        return false;
    }
    // pass 2: lowest address of the mappings of that very file (the offset 0 one is the ELF header)
    rewind(fp);
    uintptr_t lowest = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long s, e, off, ino;
        unsigned maj, min;
        char perms[8];
        const char* p;
        if (!parseMapsLine(line, &s, &e, perms, &off, &maj, &min, &ino, &p)) continue;
        if (ino != f_ino || maj != f_maj || min != f_min || off != 0) continue;
        if (lowest == 0 || s < lowest) lowest = s;
    }
    fclose(fp);
    if (lowest == 0) return false;
    *base = lowest;
    *inode = (ino_t)f_ino;
    *dev = makedev(f_maj, f_min);
    return true;
}

#if defined(__LP64__)
typedef ElfW(Rela) Reloc_t;
#define R_SYM_OF(i) ELF64_R_SYM(i)
#else
typedef ElfW(Rel) Reloc_t;
#define R_SYM_OF(i) ELF32_R_SYM(i)
#endif

struct DynInfo {
    uintptr_t bias = 0, symtab = 0, strtab = 0, jmprel = 0, rel = 0;
    size_t pltrelsz = 0, relsz = 0;
};

static bool parseDyn(uintptr_t base, DynInfo* di) {
    auto eh = (const ElfW(Ehdr)*)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return false;
    auto ph = (const ElfW(Phdr)*)(base + eh->e_phoff);
    uintptr_t min_vaddr = (uintptr_t)-1;
    uintptr_t dyn_vaddr = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            uintptr_t v = ph[i].p_vaddr & ~(uintptr_t)0xfff;
            if (v < min_vaddr) min_vaddr = v;
        } else if (ph[i].p_type == PT_DYNAMIC) {
            dyn_vaddr = ph[i].p_vaddr;
        }
    }
    if (min_vaddr == (uintptr_t)-1 || dyn_vaddr == 0) return false;
    uintptr_t bias = base - min_vaddr;
    di->bias = bias;
    auto dyn = (const ElfW(Dyn)*)(bias + dyn_vaddr);
    // bionic keeps d_ptr values as link-time vaddrs; be tolerant if they were relocated already
    auto fix = [&](uintptr_t v) -> uintptr_t { return v < base ? v + bias : v; };
    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB: di->symtab = fix(d->d_un.d_ptr); break;
            case DT_STRTAB: di->strtab = fix(d->d_un.d_ptr); break;
            case DT_JMPREL: di->jmprel = fix(d->d_un.d_ptr); break;
            case DT_PLTRELSZ: di->pltrelsz = d->d_un.d_val; break;
#if defined(__LP64__)
            case DT_RELA: di->rel = fix(d->d_un.d_ptr); break;
            case DT_RELASZ: di->relsz = d->d_un.d_val; break;
#else
            case DT_REL: di->rel = fix(d->d_un.d_ptr); break;
            case DT_RELSZ: di->relsz = d->d_un.d_val; break;
#endif
            default: break;
        }
    }
    return di->symtab && di->strtab;
}

int findGotSlots(uintptr_t base, const char* symbol, void*** out, int max) {
    DynInfo di;
    if (!parseDyn(base, &di)) return 0;
    int count = 0;
    struct Tab { uintptr_t addr; size_t size; } tabs[2] = {{di.jmprel, di.pltrelsz}, {di.rel, di.relsz}};
    for (auto& t : tabs) {
        if (!t.addr || !t.size) continue;
        auto r = (const Reloc_t*)t.addr;
        size_t n = t.size / sizeof(Reloc_t);
        for (size_t i = 0; i < n; i++) {
            uint32_t si = (uint32_t)R_SYM_OF(r[i].r_info);
            if (si == 0) continue;
            auto sy = (const ElfW(Sym)*)di.symtab + si;
            const char* name = (const char*)di.strtab + sy->st_name;
            if (strcmp(name, symbol) != 0) continue;
            if (count < max) out[count] = (void**)(di.bias + r[i].r_offset);
            count++;
        }
    }
    return count < max ? count : max;
}

static int protAt(uintptr_t addr) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return -1;
    char line[1024];
    int prot = -1;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long s, e, off, ino;
        unsigned maj, min;
        char perms[8];
        const char* p;
        if (!parseMapsLine(line, &s, &e, perms, &off, &maj, &min, &ino, &p)) continue;
        if (addr >= s && addr < e) {
            prot = (perms[0] == 'r' ? PROT_READ : 0) | (perms[1] == 'w' ? PROT_WRITE : 0) |
                   (perms[2] == 'x' ? PROT_EXEC : 0);
            break;
        }
    }
    fclose(fp);
    return prot;
}

bool patchGotSlot(void** slot, void* new_val) {
    long pg = sysconf(_SC_PAGESIZE);
    uintptr_t page = (uintptr_t)slot & ~((uintptr_t)pg - 1);
    int old_prot = protAt((uintptr_t)slot);
    if (old_prot < 0) old_prot = PROT_READ;
    if (mprotect((void*)page, pg, old_prot | PROT_READ | PROT_WRITE) != 0) {
        LOGD("ERROR mprotect rw: %s", strerror(errno));
        return false;
    }
    *slot = new_val;
    if (mprotect((void*)page, pg, old_prot) != 0) {
        LOGD("WARN mprotect restore: %s", strerror(errno));
    }
    return true;
}
