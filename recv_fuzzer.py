from winappdbg import *
from collections import deque

# Each thread will have an entry with the address of the last buffer filled by recvfrom and 
# a circular buffer with the last 32 buffers received and modified.
ThreadLocalStorage = {}

NumberOfReads = 0

def FlipRandomBytes(buffer_, max_bytes=10):
    """
    Receives a buffer and randomly changes a random number of the bytes
    """
    modified_buffer = list(buffer_)
    
    from random import randint
    
    # Get the number of random bytes to flip
    nbytes = randint(0, max_bytes)
    
    for i in xrange(0, nbytes + 1):
        offset = randint(0, len(modified_buffer) - 1)
        o_byte = modified_buffer[offset]
        modified_buffer[offset] = chr(ord(o_byte) ^ randint(0, 255))
        
    return "".join(modified_buffer)

def malloc_hook_pre(event, ra, size):
    try:
        ThreadLocalStorage[event.get_tid()]["last_alloc_size"] = size
    except KeyError:
        pass

def malloc_hook_post(event, return_value):
    try:
        alloc_size = ThreadLocalStorage[event.get_tid()]["last_alloc_size"]
        ThreadLocalStorage[event.get_tid()]["last_allocs"].append((return_value, alloc_size))
    except KeyError:
        pass

def recvfrom_hook_pre(event, ra, socket, buf, len, flags, from_addr, fromlen):
    try:
        # Set the address of the buffer in a thread local storage. This will be accessed by the post hook.
        ThreadLocalStorage[event.get_tid()]["buffer_address"] = buf
    except KeyError:
        pass

def recvfrom_hook_post(event, return_value):
    global NumberOfReads
    if NumberOfReads < 100:
        NumberOfReads += 1
        return
        
    try:
        buffer_address = ThreadLocalStorage[event.get_tid()]["buffer_address"]
    
        memory = event.get_process().peek(buffer_address, return_value)    
        modified_buffer = FlipRandomBytes(memory)
        
        ThreadLocalStorage[event.get_tid()]["last_packets"].append((memory, modified_buffer))
        
        event.get_process().poke(buffer_address, modified_buffer)
        
        print "Original bytes:"
        print HexDump.hexblock(memory, buffer_address, width=32)
        print "Fuzzed bytes:"
        print HexDump.hexblock(modified_buffer, buffer_address, width=32)
    except KeyError:
        pass

class MyEventHandler( EventHandler ):
    def __init__(self):
        self.loaded_dlls = {}
        self.logger = Logger("dump.log", False)
        super(MyEventHandler, self).__init__()

    def create_thread(self, event):
        self.logger.log_event(event, "Thread started")
        ThreadLocalStorage[event.get_tid()] = {}
        ThreadLocalStorage[event.get_tid()]["last_allocs"    ] = deque(maxlen=32)
        ThreadLocalStorage[event.get_tid()]["last_packets"   ] = deque(maxlen=8)
        ThreadLocalStorage[event.get_tid()]["last_alloc_size"] = None
        ThreadLocalStorage[event.get_tid()]["buffer_address" ] = None
        
    def __add_crash(self, event):
        # Generate a crash object.
        crash = Crash(event)
        
        """
        fetch_extra_data(self, event, takeMemorySnapshot=0)
        source code 
        Fetch extra data from the Event object.
        
        Parameters:
        event (Event) - Event object for crash.
        takeMemorySnapshot (int) - Memory snapshot behavior:
        0 to take no memory information (default).
        1 to take only the memory map. See Process.get_memory_map.
        2 to take a full memory snapshot. See Process.take_memory_snapshot.
        3 to take a full memory snapshot generator. See Process.generate_memory_snapshot.
        
        crash.fetch_extra_data(event, self.options.memory)
        """

        # Log the event to standard output.
        msg = crash.fullReport(bShowNotes = False)
        self.logger.log_event(event, msg)
        
        self.logger.log_event(event, "Last allocations:")        
        
        for tid, tls in ThreadLocalStorage.items():
            try:
                self.logger.log_event(event, "Allocations for thread %d" % (tid))
                for allocation in tls["last_allocs"]:
                    self.logger.log_event(event, "  malloc(0x%.8x) = 0x%.8")
            except KeyError:
                self.logger.log_event(event, "  No allocations")
        
        self.logger.log_event(event, "Disassembly around crash:")
        disassembly = event.get_process().disassemble_around_pc(event.get_tid())
        for line in CrashDump.dump_code(disassembly).split("\n"):
            self.logger.log_event(event, line)
        
        self.logger.log_event(event, "Last fuzzed packets:")
        # For each of the buffers modified
        for tid, tls in ThreadLocalStorage.items():
            self.logger.log_event(event, "Dumping packets for thread %d" % (tid))
            
            try:
                # For each packet in the circular buffer
                for packet in tls["last_packets"]:
                    self.logger.log_event(event, HexDump.hexblock(packet[1], 0, width=32))
            except KeyError:
                self.logger.log_event(event, "No packets")
                
    # Get the location of the code that triggered the event.
    def __get_location(self, event, address):
        label = event.get_process().get_label_at_address(address)
        if label:
            return label
        
        return HexDump.address(address)
    
    # Log an exception as a single line of text.
    def __log_exception(self, event):
        what    = event.get_exception_description()
        address = event.get_exception_address()
        where   = self.__get_location(event, address)
        
        if event.is_first_chance():
            chance = 'first'
        else:
            chance = 'second'
            
        msg = "%s (%s chance) at %s (%x)" % (what, chance, where, address)
        self.logger.log_event(event, msg)
        
    # Kill the process if it's a second chance exception.
    def _post_exception(self, event):
        if event.is_last_chance():
            try:
                event.get_thread().set_pc(event.get_process().resolve_symbol('kernel32!ExitProcess'))
            except Exception:
                event.get_process().kill()

    # Handle all exceptions not handled by the following methods.
    def exception(self, event):
        self.__log_exception(event)
        if event.is_last_chance():
            self.__add_crash(event)
            
        self._post_exception(event)

    # Unknown (most likely C++) exceptions are not crashes.
    def unknown_exception(self, event):
        # Log the event to standard output.
        self.__log_exception(event)
        #if event.is_last_chance():
        #    self.__add_crash(event)
            
        self._post_exception(event)

    # Microsoft Visual C exceptions are not crashes.
    def ms_vc_exception(self, event):
        # Log the event to standard output.
        self.__log_exception(event)
        #if event.is_last_chance():
        #    self.__add_crash(event)

        self._post_exception(event)
        
    def load_dll( self, event ):
        # Get the new module object
        module = event.get_module()

        if module.match_name("Ws2_32.dll") or module.match_name("wsock32.dll"):
            # Get the process ID
            pid = event.get_pid()
            
            address = module.resolve( "recvfrom" )
            event.debug.hook_function( pid, address, preCB=recvfrom_hook_pre, postCB=recvfrom_hook_post, paramCount=6)

            #address = module.resolve( "recv" )
            #event.debug.hook_function( pid, address, preCB=recv_hook_pre, postCB=recv_hook_post, paramCount=4)

        """
        if module.match_name("MSVCR90.dll"):
            # Get the process ID
            pid = event.get_pid()
            
            address = module.resolve("malloc")
            event.debug.hook_function( pid, address, preCB=malloc_hook_pre, postCB=malloc_hook_post, paramCount=1)
        """
        
        lpBaseOfDll = module.get_base()
        fileName    = module.get_filename()

        # Do not log already loaded dlls
        if self.loaded_dlls.has_key(fileName):
            if self.loaded_dlls[fileName] == lpBaseOfDll:
                return
            
        # Update the previous addres of this dll
        self.loaded_dlls[fileName] = lpBaseOfDll
            
        if not fileName:
            fileName = "a new module"
            
        msg = "Loaded %s at %s"
        msg = msg % (fileName, HexDump.address(lpBaseOfDll))
        self.logger.log_event(event, msg)

def simple_debugger( argv ):
    # Instance a Debug object, passing it the MyEventHandler instance
    debug = Debug( MyEventHandler() )
    try:

        # Start a new process for debugging
        debug.execv( argv )

        # Wait for the debugee to finish
        debug.loop()

    # Stop the debugger
    finally:
        debug.stop()


# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process
if __name__ == "__main__":
    import sys
    simple_debugger( sys.argv[1:] )
