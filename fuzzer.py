import sys
import optparse

from winappdbg import win32
from winappdbg import Debug, EventHandler, System, Process, MemoryAddresses
from winappdbg import HexInput, HexDump, Logger

logger = Logger(logfile=None, verbose=True)

def main(argv):
    options = parse_cmdline(argv)

    # Create the event handler object
    eventHandler = EventForwarder(MemoryWatcher, options)

    # Create the debug object
    debug = Debug(eventHandler, bKillOnExit=True)
    
    try:

        # Attach to the targets
        for pid in options.attach:
            logger.log_text("Attaching to %d" % pid)
            debug.attach(pid)
            
        # Run the debug loop
        debug.loop()

    # Stop the debugger
    finally:
        debug.stop()

def parse_cmdline( argv ):

    # Help message and version string
    version = ("In Memory fuzzer\n")
    
    usage = (
            "\n"
            "\n"
            "  Attach to a running process (by filename):\n"
            "    %prog [options] -a <executable>\n"
            "\n"
            "  Attach to a running process (by ID):\n"
            "    %prog [options] -a <process id>"
            )
    
    parser = optparse.OptionParser(
                                    usage=usage,
                                    version=version,
                                  )

    # Commands
    commands = optparse.OptionGroup(parser, "Commands")
    
    commands.add_option("-a", "--attach", action="append", type="string",
                        metavar="PROCESS",
                        help="Attach to a running process")
    
    parser.add_option_group(commands)

    # SEH test options
    fuzzer_opts = optparse.OptionGroup(parser, "Fuzzer options")
    
    fuzzer_opts.add_option("--snapshot_address", metavar="ADDRESS",
                       help="take snapshot point address")

    fuzzer_opts.add_option("--restore_address", metavar="ADDRESS",
                       help="restore snapshot point address")

    fuzzer_opts.add_option("--buffer_address", metavar="ADDRESS",
                       help="address of the buffer to be modified in memory")

    fuzzer_opts.add_option("--buffer_size", metavar="ADDRESS",
                       help="size of the buffer to be modified in memory")
    
    fuzzer_opts.add_option("-o", "--output", metavar="FILE",
                       help="write the output to FILE")
    
    fuzzer_opts.add_option("--debuglog", metavar="FILE",
                       help="set FILE as a debug log (extremely verbose!)")
    
    parser.add_option_group(fuzzer_opts)

    # Debugging options
    debugging = optparse.OptionGroup(parser, "Debugging options")
    
    debugging.add_option("--follow", action="store_true",
                  help="automatically attach to child processes [default]")
    
    debugging.add_option("--dont-follow", action="store_false", dest="follow",
                  help="don't automatically attach to child processes")
    
    parser.add_option_group(debugging)

    # Defaults
    parser.set_defaults(
        follow      = True,
        attach      = list(),
        output      = None,
        debuglog    = None,
    )

    # Parse and validate the command line options
    if len(argv) == 1:
        argv = argv + [ '--help' ]
    (options, args) = parser.parse_args(argv)
    args = args[1:]
    if not options.attach:
        if not args:
            parser.error("missing target application(s)")
        options.console = [ args ]
    else:
        if args:
            parser.error("don't know what to do with extra parameters: %s" % args)

    if not options.snapshot_address:
        parser.error("Snapshot address not specified")
            
    if not options.restore_address:
        parser.error("Restore address not specified")
    
    if not options.buffer_address:
        parser.error("Buffer address not specified")
    
    if not options.buffer_size:
        parser.error("Buffser size not specified")
        
        

    global logger
    if options.output:
        logger = Logger(logfile = options.output, verbose = logger.verbose)

    # Open the debug log file if requested
    if options.debuglog:
        logger = Logger(logfile = options.debuglog, verbose = logger.verbose)

    # Get the list of attach targets
    system = System()
    system.request_debug_privileges()
    system.scan_processes()
    attach_targets = list()
    
    for token in options.attach:
        try:
            dwProcessId = HexInput.integer(token)
        except ValueError:
            dwProcessId = None
        if dwProcessId is not None:
            if not system.has_process(dwProcessId):
                parser.error("can't find process %d" % dwProcessId)
            try:
                process = Process(dwProcessId)
                process.open_handle()
                process.close_handle()
            except WindowsError, e:
                parser.error("can't open process %d: %s" % (dwProcessId, e))
            attach_targets.append(dwProcessId)
        else:
            matched = system.find_processes_by_filename(token)
            if not matched:
                parser.error("can't find process %s" % token)
            for process, name in matched:
                dwProcessId = process.get_pid()
                try:
                    process = Process(dwProcessId)
                    process.open_handle()
                    process.close_handle()
                except WindowsError, e:
                    parser.error("can't open process %d: %s" % (dwProcessId, e))
                attach_targets.append( process.get_pid() )
    options.attach = attach_targets

    # If no targets were set at all, show an error message
    if not options.attach:
        parser.error("no targets found!")

    return options


class EventForwarder(EventHandler):
    def __init__(self, cls, options):
        self.cls     = cls
        self.options = options
        self.forward = dict()
        super(EventForwarder, self).__init__()

    def event(self, event):
        #logger.log_event(event)
        
        pid = event.get_pid()
        if self.forward.has_key(pid):
            return self.forward[pid](event)

    def create_process(self, event):
        logger.log_event(event)
        handler = self.cls(self.options)
        self.forward[event.get_pid()] = handler
        return handler(event)

    def exit_process(self, event):
        logger.log_event(event)
        
        pid = event.get_pid()
        if self.forward.has_key(pid):
            retval = self.forward[pid](event)
            del self.forward[pid]
            return retval

    def breakpoint(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        #logger.log_event(event)

    def wow64_breakpoint(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        logger.log_event(event)

    def debug_control_c(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        logger.log_event(event)

    def invalid_handle(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        logger.log_event(event)

    def possible_deadlock(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        logger.log_event(event)

class MemoryFuzzer:
    def __init__(self, buffer_address, buffer_size):
        self.buffer_adddress = buffer_address
        self.buffer_size = buffer_size 
        self.cur_byte = 0
        self.fuzz_values = ['\xca', '\xfe']
        self.cur_fuzz_val = 0
        self.buffer_backup = None
        
        
    def iterate(self, event):
        #logger.log_text("iterating")            
        if self.cur_byte >= self.buffer_size:
            return False

        p = event.get_process()
        
        # make a copy of the original buffer
        if not self.buffer_backup:
            self.buffer_backup= p.read(self.buffer_adddress, self.buffer_size)
        
        if self.cur_fuzz_val == len(self.fuzz_values):
            # restore the original byte
            p.write(self.buffer_adddress + self.cur_byte, self.buffer_backup[self.cur_byte])

            # fuzz next byte using the first fuzz value
            self.cur_byte += 1
            self.cur_fuzz_val = 0
            
        
        p.write(self.buffer_adddress + self.cur_byte, self.fuzz_values[self.cur_fuzz_val])
        
        # next fuzz value
        self.cur_fuzz_val += 1
        
        #from winappdbg import HexDump
        #logger.log_text(HexDump.hexblock(self.buffer_backup, self.buffer_adddress))
        
        return True
        

class MemoryWatcher(EventHandler):
    protect_conversions = {
        win32.PAGE_EXECUTE_READWRITE:   win32.PAGE_EXECUTE_READ,
        win32.PAGE_EXECUTE_WRITECOPY:   win32.PAGE_EXECUTE_READ,
        win32.PAGE_READWRITE:           win32.PAGE_READONLY,
        win32.PAGE_WRITECOPY:           win32.PAGE_READONLY,
    }
    
    def __init__(self, options):
        super(MemoryWatcher, self).__init__()
        
        self.options = options
        
        self.fuzzing = False
        
        # create an instance of our in memory fuzzer
        self.fuzzer = MemoryFuzzer(int(self.options.buffer_address, 16), int(self.options.buffer_size))
                
    def create_process(self, event):
        """
        When attaching to a process, when starting a new process for debugging, 
        or when the debugee starts a new process and the bFollow flag was set to True.
        """
        self.debug   = event.debug
        self.pid     = event.get_pid()
        self.process = event.get_process()
        
        # When a new process is created we need to setup the triggers of snapshots
        self.debug.break_at(self.pid, int(self.options.snapshot_address, 16), self.onTakeSnapshotEvent)
        self.debug.break_at(self.pid, int(self.options.restore_address, 16), self.onRestoreSnapshotEvent)        

        
    def onModifyBufferEvent(self, event):
        return self.fuzzer.iterate(event)
    
    def onTakeSnapshotEvent(self, event):
        """
        Triggered when the target application is about to use the memory buffer
        we are fuzzing. This event will trigger a pseudo snapshot of memory in which
        all the pages are set as read only, only when the pages are written by the application
        its contents are saved for posterior use (to revert the snapshot).
        """
        # if we are currently fuzzing
        if self.fuzzing:
            # Syntethic event
            if not self.onModifyBufferEvent(event):
                # We finished fuzzing, let the program run and see if it ends up crashing.
                # If it did crash, it could mean that we found a bug or there was some state
                # that the memory snapshots could not revert and the application ended up in a 
                # weird state.
                logger.log_text("Finished fuzzing, letting the application run.")            
                
                # Restore the snapshot and set back the original page permissions
                self.cleanupSnapshot()
                
                # Remove all the breakpoints we could have set.
                self.debug.erase_all_breakpoints()
                
                # Resume the rest of the threads.
                self.resumeOtherThreads()

            return
        else:
            self.fuzzing = True 
                
            self.tid    = event.get_tid()
            self.thread = event.get_thread()
            
            # We suspend other threads hoping that they have nothing to do with the parsing of the fuzzed buffer.
            self.suspendOtherThreads()
            
            # Set all the memory as read only and only when the pages are written save a copy
            self.takeSnapshot()
            
    def onRestoreSnapshotEvent(self, event):
        #logger.log_text(("*" * 8 ) + "restore snapshot event" + ("*" * 8 ))
        self.restoreSnapshot()
    
    def create_thread(self, event):
        """
        When the process creates a new thread or when the 
        _Process.start_thread_ method is called.
        """
        #logger.log_text("create_thread()")
        pass

    def exception(self, event):
        if event.is_first_chance():
            event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED

            if self.checkSnapshotPage(event):
                # We received an error that had to do with our saved pages
                event.continueStatus = win32.DBG_CONTINUE
            else:
                # This is a completely different error, probably a bug. Log and restart
                logger.log_text("")
                logger.log_text(("=" * 8) + "Bug found" + ("=" * 8))
                logger.log_event(event)
                logger.log_text("=" * 25)
                
                event.continueStatus = win32.DBG_CONTINUE
                
                self.restoreSnapshot()
        else:
            event.continueStatus = win32.DBG_EXCEPTION_HANDLED            
            self.checkSnapshotPage(event)

    def suspendOtherThreads(self):
        logger.log_text("Suspending other threads")
        
        for thread in self.process.iter_threads():
            if thread.get_tid() != self.tid:
                thread.suspend()

    def resumeOtherThreads(self):
        logger.log_text("Resuming other threads")
        
        for thread in self.process.iter_threads():
            if thread.get_tid() != self.tid:
                thread.resume()

    def takeSnapshot(self):
        """
        Called from the take snapshot event. This was fired by a breakpoint on an address
        that the user specified as the point where everything should be restored on the
        next fuzz iteration. 
        
        NOTE: Que pasa con los contextos de los otros threads??? Se podram resumir en el mismo estado?
        Creo que si y deberiamos hacerlo.
        """
        #logger.log_text("Taking snapshot of the process")
        
        # Take a snapshot of the contex of the current thread
        self.context = self.thread.get_context()

        pageSize = System.pageSize

        # Save also special pages like the PEB
        self.special_pages = dict()
        page = MemoryAddresses.align_address_to_page_start(self.process.get_peb_address())
        self.special_pages[page] = self.process.read(page, pageSize)
        
        # Also do this for other threads
        for thread in self.process.iter_threads():
            page = MemoryAddresses.align_address_to_page_start(thread.get_teb_address())
            self.special_pages[page] = self.process.read(page, pageSize)

        self.memory = dict()
        self.tainted = set()
        
        # For each memory map in memory
        for mbi in self.process.get_memory_map():
            # We only care about those who are writable
            if mbi.is_writeable():
                page = mbi.BaseAddress
                max_page = page + mbi.RegionSize
                
                # For each page
                while page < max_page:
                    # if it is not a special page
                    if not self.special_pages.has_key(page):
                        # Save the old protection permissions
                        protect = mbi.Protect
                        new_protect = self.protect_conversions[protect]
                        try:
                            self.process.mprotect(page, pageSize, new_protect)
                            self.memory[page] = (None, protect, new_protect)
                        except WindowsError:
                            # if we have a weird error, mark it as a special page
                            self.special_pages[page] = self.process.read(page, pageSize)
                            logger.log_text("unexpected special page %s" % HexDump.address(page))
                            
                    # next page
                    page = page + pageSize

    def restoreSnapshot(self):
        #logger.log_text("Restoring snapshot")
        
        # Restore thread context.
        self.thread.set_context(self.context)
        
        pageSize = System.pageSize
        process = self.process
        tainted = self.tainted
        
        # Restore each special page content (PEB etc.)
        for page, content in self.special_pages.iteritems():
            process.write(page, content)
            
        
        for page, (content, protect, new_protect) in self.memory.iteritems():
            if page in tainted:
                process.write(page, content)
                process.mprotect(page, pageSize, new_protect)
                tainted.remove(page)

    def checkSnapshotPage(self, event):
        if event.get_tid() == self.tid:
            try:
                fault_type = event.get_fault_type()
            except AttributeError:
                fault_type = None
            except NotImplementedError:
                fault_type = None
                
            if fault_type == win32.EXCEPTION_WRITE_FAULT:
                address = event.get_fault_address()
                page = MemoryAddresses.align_address_to_page_start(address)
                
                #logger.log_text("write fault at page %08x address %08x" % (page, address))
                
                if self.memory.has_key(page):
                    (content, protect, new_protect) = self.memory[page]
                    content = self.process.read(page, System.pageSize)
                    self.memory[page] = (content, protect, new_protect)
                    self.tainted.add(page)
                    self.process.mprotect(page, System.pageSize, protect)
                    return True
                    
        return False

    def cleanupSnapshot(self):
        self.restoreSnapshot()

        pageSize = System.pageSize
        for page, (content, protect, new_protect) in self.memory.iteritems():
            self.process.mprotect(page, pageSize, protect)

from ctypes import windll, Structure, sizeof, WinError, byref, create_string_buffer, c_void_p, cast
from winappdbg.win32.defines import PVOID, ULONG, PULONG, NTSTATUS, DWORD, BYTE, USHORT
from winappdbg.win32.ntdll import RtlNtStatusToDosError

SYSTEM_INFORMATION_CLASS = DWORD
ACCESS_MASK = DWORD

# typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
# {
#     ULONG ProcessId;
#     BYTE ObjectTypeNumber;
#     BYTE Flags;
#     USHORT Handle;
#     PVOID Object;
#     ACCESS_MASK GrantedAccess;
# } SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
class SYSTEM_HANDLE_TABLE_ENTRY_INFO(Structure):
    _fields_ = [
        ("ProcessId",           ULONG),
        ("ObjectTypeNumber",    BYTE),
        ("Flags",               BYTE),
        ("Handle",              USHORT),
        ("Object",              PVOID),
        ("GrantedAccess",       ACCESS_MASK), 
]

# typedef struct _SYSTEM_HANDLE_INFORMATION
# {
#     ULONG HandleCount; /* Or NumberOfHandles if you prefer. */
#     SYSTEM_HANDLE Handles[1];
# } SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
class SYSTEM_HANDLE_INFORMATION(Structure):
    _fields_ = [
        ("HandleCount",         ULONG),
        ("Handles",             SYSTEM_HANDLE_TABLE_ENTRY_INFO * 1),
]


SystemHandleInformation = 16
STATUS_INFO_LENGTH_MISMATCH  = 0xc0000004

# NTSTATUS WINAPI NtQuerySystemInformation(
#   __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
#   __inout    PVOID SystemInformation,
#   __in       ULONG SystemInformationLength,
#   __out_opt  PULONG ReturnLength
# );
def NtQuerySystemInformation(SystemInformationClass):
    _NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
    _NtQuerySystemInformation.argtypes = [SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG]
    _NtQuerySystemInformation.restype = NTSTATUS
    
    if SystemInformationClass != SystemHandleInformation:
        raise NotImplementedError("I am lazy and just implemented what _I_ needed.")
    
    SystemInformation = SYSTEM_HANDLE_INFORMATION()
    SystemInformationLength = sizeof(SYSTEM_HANDLE_INFORMATION)

    ReturnLength = ULONG(0)
    
    ntstatus = -1
    while ntstatus != 0:
        ntstatus = _NtQuerySystemInformation(SystemInformationClass, byref(SystemInformation), SystemInformationLength, ReturnLength)
        SystemInformationLength *= 2
        SystemInformation = create_string_buffer("", SystemInformationLength)
            
    #from ctypes import pointer, addressof
    #vptr = pointer(addressof(*))
    #print vptr
    #cptr = cast( vptr, SYSTEM_HANDLE_INFORMATION)
    #print cptr

    return SystemInformation

if __name__ == "__main__":    
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    
    main(sys.argv)
    
