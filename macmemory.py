from utils import align

''' Very basic support for Macintosh-style memory manager '''

# basic memory manager areas
HANDLE_START = 0x10000 # begin of the memory block for storing handles
HANDLE_SIZE  = 0x08000 # size of the handles block
MEM_START    = 0x20000 # begin of the allocatable memory block
MEM_SIZE     = 0x50000 # size of the allocatable memory

class MemoryException(Exception):
    def __init__(self, msg):
        self._msg = msg

class MacMemory:
    def __init__(self, rt):
        self._mem = rt.get_mem()
        self._next_handle = HANDLE_START
        self._next_ptr    = MEM_START
        self._mem_blocks  = {}

    def _alloc_handle(self):
        if (self._next_handle + 4) > (HANDLE_START + HANDLE_SIZE):
            raise MemoryException("Out of handles mem!")
        handle = self._next_handle
        self._next_handle += 4
        return handle

    def alloc_mem(self, size):
        size_align = align(size, 16)
        print("alloc_mem: size %X, aligned size %X" % (size, size_align))
        if (self._next_ptr + size_align) > (MEM_START + MEM_SIZE):
            raise MemoryException("Out of allocatable memory!")
        ptr = self._next_ptr
        self._next_ptr += size_align
        self._mem_blocks[ptr] = size # memorize blocks sizes
        print("alloc_mem: allocated new memory block, addr=%X, size=%X" % (ptr, size))
        return ptr

    def new_handle(self, size, zero=False):
        if size == 0:
            new_ptr = 0
        else:
            new_ptr = self.alloc_mem(size)
        new_handle = self._alloc_handle()
        self._mem.w32(new_handle, new_ptr) # set up virtual memory appropriately
        if zero:
            for i in range(size):
                self._mem.w8(new_ptr + i, 0)
        return new_handle

    def recover_handle(self, ptr):
        hsize = self._next_handle - HANDLE_START
        for offset in range(0, hsize, 4):
            if self._mem.r32(HANDLE_START + offset) == ptr:
                return HANDLE_START + offset
        raise MemoryException("Could not recover handle for %X" % ptr)

    def get_handle_size(self, handle):
        ptr = self._mem.r32(handle)
        if ptr not in self._mem_blocks:
            raise MemoryException("Unregistered memory block at %X!" % ptr)
        return self._mem_blocks[ptr]
