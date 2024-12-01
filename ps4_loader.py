from binaryninja import *
import struct
import csv
import os
from os.path import exists
import shutil

def load_nids(location, nids = {}):
    try:
        with open(location) as database:
            nids = dict(row for row in csv.reader(database, delimiter=' '))
    except IOError:
        nidsDialog = OpenFileNameField("Select aerolib.csv", 'aerolib.csv|*.csv|All files (*.*)|*.*')

        if not get_form_input([nidsDialog], "Select aerolib.csv"):
            return log_error("File not selected, try again!")

        if not exists(nidsDialog.result):
            return log_error("File not found, try again!")
        
        try:
            with open(nidsDialog.result) as database:
                nids = dict(row for row in csv.reader(database, delimiter=' '))
                
                shutil.copy2(nidsDialog.result, location)
                    
        except Exception as e:
            log_error(f'Failed to load nids! Exception: {e}')

    
    return nids

class PS4ELF(BinaryView):
    name = "PS4 ELF"
    long_name = "PS4 ELF"

    # Elf types
    ET_NONE                   = 0x0
    ET_REL                    = 0x1
    ET_EXEC                   = 0x2
    ET_DYN                    = 0x3
    ET_CORE                   = 0x4
    ET_SCE_EXEC               = 0xFE00
    ET_SCE_REPLAY_EXEC        = 0xFE01
    ET_SCE_RELEXEC            = 0xFE04
    ET_SCE_STUBLIB            = 0xFE0C
    ET_SCE_DYNEXEC            = 0xFE10
    ET_SCE_DYNAMIC            = 0xFE18
    ET_LOPROC                 = 0xFF00
    ET_HIPROC                 = 0xFFFF

    # Elf architecture
    EM_X86_64                 = 0x3E

    def __init__(self, data):
        """
        Initialize the Plugin, grabs default BinaryView.
        """
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.arch = Architecture["x86_64"]
        self.platform = self.arch.standalone_platform  # type: ignore
        self.raw = data
        self.reader = BinaryReader(self.raw, Endianness.LittleEndian)
        self.nid_database = None
        self.struct_endianness = "<"  # Little endian for struct unpacking

    @staticmethod
    def is_valid_for_data(data):
        hdr = data.read(0, 0x40)
        if len(hdr) < 0x40:
            return False
        if hdr[1:4] != b'ELF':
            return False

        return True

    def init(self):
        self.nids = load_nids(os.path.dirname(os.path.abspath(__file__)) + '/aerolib.csv')
        
        try:
            self.parse_elf()
            self.parse_sce()
            log_info("Symbols added successfully.")

        except Exception as e:
            log_error(f"Error adding symbols: {e}")

        return True
    
    def parse_elf(self):
        """
        Parse the ELF and program headers
        """
        f = self.reader
        self.EI_MAGIC         = struct.unpack('4s', f.read(4))[0]
        self.EI_CLASS         = struct.unpack('<B', f.read(1))[0]
        self.EI_DATA          = struct.unpack('<B', f.read(1))[0]
        self.EI_VERSION       = struct.unpack('<B', f.read(1))[0]
        self.EI_OSABI         = struct.unpack('<B', f.read(1))[0]
        self.EI_ABIVERSION    = struct.unpack('<B', f.read(1))[0]
        self.EI_PADDING       = struct.unpack('6x', f.read(6))
        self.EI_SIZE          = struct.unpack('<B', f.read(1))[0]
        
        # Elf Properties
        self.E_TYPE           = struct.unpack('<H', f.read(2))[0]
        self.E_MACHINE        = struct.unpack('<H', f.read(2))[0]
        self.E_VERSION        = struct.unpack('<I', f.read(4))[0]
        self.E_START_ADDR     = struct.unpack('<Q', f.read(8))[0]
        self.E_PHT_OFFSET     = struct.unpack('<Q', f.read(8))[0]
        self.E_SHT_OFFSET     = struct.unpack('<Q', f.read(8))[0]
        self.E_FLAGS          = struct.unpack('<I', f.read(4))[0]
        self.E_SIZE           = struct.unpack('<H', f.read(2))[0]
        self.E_PHT_SIZE       = struct.unpack('<H', f.read(2))[0]
        self.E_PHT_COUNT      = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_SIZE       = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_COUNT      = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_INDEX      = struct.unpack('<H', f.read(2))[0]

        if self.E_MACHINE != PS4ELF.EM_X86_64:
             raise Exception("Unsupported ELF machine (only 64-bit supported)")

        self.E_SEGMENTS = [Segment(self.reader) for entry in range(self.E_PHT_COUNT)]

        self.reader.seek(self.E_SHT_OFFSET)

        self.E_SECTION = [Section(self.reader) for entry in range(self.E_SHT_COUNT)]


    def perform_get_address_size(self) -> int:
        return self.arch.address_size

    def parse_sce(self):
        for segm in self.E_SEGMENTS:
            if segm.name() in ['CODE', 'DATA', 'SCE_RELRO', 'DYNAMIC', 'GNU_EH_FRAME', 'SCE_DYNLIBDATA']:
                address = segm.MEM_ADDR if segm.name() not in ['DYNAMIC', 'SCE_DYNLIBDATA'] else segm.OFFSET + 0x1000000
                size    = segm.MEM_SIZE if segm.name() not in ['DYNAMIC', 'SCE_DYNLIBDATA'] else segm.FILE_SIZE
                print('# Processing %s Segment...' % segm.name())
                if segm.name() not in ['DYNAMIC', 'GNU_EH_FRAME']:
                    self.add_auto_segment(address, size, segm.OFFSET, segm.FILE_SIZE, segm.type())
                    self.add_auto_section(segm.name(), address, size, segm.section_type())
                elif segm.name() == 'DYNAMIC':
                    stubs = {}
                    modules = {}
                    libraries = {}
                    self.reader.seek(segm.OFFSET)
                    
                    offset = segm.OFFSET
                    dynamic = address
                    dynamicsize = size
                    for entry in range(int(dynamicsize / 0x10)):
                        self.define_data_var(address + (entry * 0x10), self.parse_type_string("int")[0])
                        self.set_comment_at(address + (entry * 0x10), Dynamic(self).process(stubs, modules, libraries))
            
            if segm.name() == 'SCE_DYNLIBDATA':
                self.define_data_var(address, "uint8_t[0x14]", "SCE_FINGERPRINT")
                try:
                    # --------------------------------------------------------------------------------------------------------
                    # Dynamic Symbol Entry Structure
                    members = [('name', 'Name (String Index)', 0x4),
                            ('info', 'Info (Binding : Type)', 0x1),
                            ('other', 'Other', 0x1),
                            ('shtndx', 'Section Index', 0x2),
                            ('value', 'Value', 0x8),
                            ('size', 'Size', 0x8)]
                    struct = segm.struct(members)
                    self.define_user_type('Symbol', struct)
                    # Dynamic Symbol Table
                    location = address + Dynamic.SYMTAB
                    self.reader.seek(segm.OFFSET + Dynamic.SYMTAB)
                    symbols = {}
                    for entry in range(int(Dynamic.SYMTABSZ / 0x18)):
                        self.define_data_var(location + (entry * 0x18), "Symbol")
                        self.set_comment_at(location + (entry * 0x18), SCESymbol(self).process(symbols))
                    
                except Exception as e:
                    traceback.print_exc()
                
                # Dynamic String Table
                try:
                    # --------------------------------------------------------------------------------------------------------
                    # Dynamic String Table
                    location = address + Dynamic.STRTAB
                    self.reader.seek(segm.OFFSET + Dynamic.STRTAB)
                    
                    # Stubs
                    for key in stubs:
                        stubs[key] = self.get_ascii_string_at(location + key).value
                    
                    #print('Stubs: %s' % stubs)
                    
                    # Modules
                    for key in modules:
                        modules[key] = self.get_ascii_string_at(location + key).value
                    
                    #print('Modules: %s' % modules)
                    
                    # Libraries and LIDs
                    lids = {}
                    for key, value in libraries.items():
                        lids[value] = self.get_ascii_string_at(location + key).value
                        libraries[key] = self.get_ascii_string_at(location + key).value
                    
                    #print('LIDs: %s' % lids)
                    
                    # Symbols
                    for key in symbols:
                        symbols[key] = self.get_ascii_string_at(location + key).value
                    
                    #print('Symbols: %s' % symbols)
                    
                except:
                    traceback.print_exc()
                
                try:
                    symbols = sorted(symbols.items())
                    location = address + Dynamic.SYMTAB + 0x30
                    self.reader.seek(segm.OFFSET + Dynamic.SYMTAB + 0x30)
                    
                    for entry in range(int((Dynamic.SYMTABSZ - 0x30) / 0x18)):
                        SCESymbol(self).resolve(location + (entry * 0x18), self.nids, symbols[entry][1])
                    
                except Exception as e:
                    traceback.print_exc()

                try:
                    # --------------------------------------------------------------------------------------------------------
                    # Jump Entry Structure
                    members = [('offset', 'Offset (String Index)', 0x8),
                            ('info', 'Info (Symbol Index : Relocation Code)', 0x8),
                            ('addend', 'AddEnd', 0x8)]
                    struct = segm.struct(members)
                    self.define_user_type('Jump', struct)
                    # PS4 Base64 Alphabet
                    base64 = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-')
                    alphabet = { character:index for index, character in enumerate(base64) }
                    #print('Base64 Table: %s' % alphabet)
                    
                    # Jump Table
                    location = address + Dynamic.JMPTAB
                    self.reader.seek(segm.OFFSET + Dynamic.JMPTAB)
                    
                    for entry in range(int(Dynamic.JMPTABSZ / 0x18)):
                        self.define_data_var(location + (entry * 0x18), "Jump")
                        self.set_comment_at(location + (entry * 0x18), Relocation(self).resolve(alphabet, self.nids, symbols, lids))
                    
                except Exception as e:
                    traceback.print_exc() 

                try:
                    # --------------------------------------------------------------------------------------------------------
                    # Relocation Entry Structure (with specific addends)
                    members = [('offset', 'Offset (String Index)', 0x8),
                            ('info', 'Info (Symbol Index : Relocation Code)', 0x8),
                            ('addend', 'AddEnd', 0x8)]
                    struct = segm.struct(members)
                    self.define_user_type('Relocation', struct)

                    # Relocation Table (with specific addends)
                    location = address + Dynamic.RELATAB
                    self.reader.seek(segm.OFFSET + Dynamic.RELATAB)
                    
                    for entry in range(int(Dynamic.RELATABSZ / 0x18)):
                        self.define_data_var(location + (entry * 0x18), "Relocation")
                        self.set_comment_at(location + (entry * 0x18), Relocation(self).process(self.nids, symbols))
                
                except Exception as e:
                    traceback.print_exc()

                # Hash Table
                try:
                    # --------------------------------------------------------------------------------------------------------
                    # Hash Entry Structure
                    members = [('bucket', 'Bucket', 0x2),
                            ('chain', 'Chain', 0x2),
                            ('buckets', 'Buckets', 0x2),
                            ('chains', 'Chains', 0x2)]
                    struct = segm.struct(members)
                    self.define_user_type('Hash', struct)
                    # Hash Table
                    location = address + Dynamic.HASHTAB
                    self.reader.seek(segm.OFFSET + Dynamic.HASHTAB)
                    
                    for entry in range(int(Dynamic.HASHTABSZ / 0x8)):
                        self.define_data_var(location + (entry * 0x8), "Hash")
                    
                except Exception as e:
                    traceback.print_exc()

                # Dynamic Tag Table
                try:
                    # --------------------------------------------------------------------------------------------------------
                    # Dynamic Tag Entry Structure
                    members = [('tag', 'Tag', 0x8),
                            ('value', 'Value', 0x8)]
                    struct = segm.struct(members)
                    self.define_user_type('Tag', struct)
                    self.reader.seek(offset)
                    
                    for entry in range(int(dynamicsize / 0x10)):
                        self.define_data_var(dynamic + (entry * 0x10), "Tag")
                        self.set_comment_at(dynamic + (entry * 0x10), Dynamic(self).comment(address, stubs, modules, libraries))
                    
                except Exception as e:
                    traceback.print_exc()
        
        if self.E_START_ADDR != 0:
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.E_START_ADDR, "_start"))
            self.add_entry_point(self.E_START_ADDR)


    def type(self):
    
        return {
            PS4ELF.ET_NONE            : 'None',
            PS4ELF.ET_REL             : 'Relocatable',
            PS4ELF.ET_EXEC            : 'Executable',
            PS4ELF.ET_DYN             : 'Shared Object',
            PS4ELF.ET_CORE            : 'Core Dump',
            PS4ELF.ET_SCE_EXEC        : 'Main Module',
            PS4ELF.ET_SCE_REPLAY_EXEC : 'Replay Module',
            PS4ELF.ET_SCE_RELEXEC     : 'Relocatable PRX',
            PS4ELF.ET_SCE_STUBLIB     : 'Stub Library',
            PS4ELF.ET_SCE_DYNEXEC     : 'Main Module - ASLR',
            PS4ELF.ET_SCE_DYNAMIC     : 'Shared Object PRX',
        }.get(self.E_TYPE, 'Missing Program Type!!!')


class SCESymbol:

    __slots__ = ('NAME', 'INFO', 'OTHER', 'SHINDEX', 'VALUE', 'SIZE', 'bv')
    
    # Symbol Information
    ST_LOCAL_NONE      = 0x0
    ST_LOCAL_OBJECT    = 0x1
    ST_LOCAL_FUNCTION  = 0x2
    ST_LOCAL_SECTION   = 0x3
    ST_LOCAL_FILE      = 0x4
    ST_LOCAL_COMMON    = 0x5
    ST_LOCAL_TLS       = 0x6
    ST_GLOBAL_NONE     = 0x10
    ST_GLOBAL_OBJECT   = 0x11
    ST_GLOBAL_FUNCTION = 0x12
    ST_GLOBAL_SECTION  = 0x13
    ST_GLOBAL_FILE     = 0x14
    ST_GLOBAL_COMMON   = 0x15
    ST_GLOBAL_TLS      = 0x16
    ST_WEAK_NONE       = 0x20
    ST_WEAK_OBJECT     = 0x21
    ST_WEAK_FUNCTION   = 0x22
    ST_WEAK_SECTION    = 0x23
    ST_WEAK_FILE       = 0x24
    ST_WEAK_COMMON     = 0x25
    ST_WEAK_TLS        = 0x26
    
    def __init__(self, bv):
        f = bv.reader
        self.bv = bv
        self.NAME      = struct.unpack('<I', f.read(4))[0]
        self.INFO      = struct.unpack('<B', f.read(1))[0]
        self.OTHER     = struct.unpack('<B', f.read(1))[0]
        self.SHINDEX   = struct.unpack('<H', f.read(2))[0]
        self.VALUE     = struct.unpack('<Q', f.read(8))[0]
        self.SIZE      = struct.unpack('<Q', f.read(8))[0]
    
    def info(self):
    
        return {
            SCESymbol.ST_LOCAL_NONE      : 'Local : None',
            SCESymbol.ST_LOCAL_OBJECT    : 'Local : Object',
            SCESymbol.ST_LOCAL_FUNCTION  : 'Local : Function',
            SCESymbol.ST_LOCAL_SECTION   : 'Local : Section',
            SCESymbol.ST_LOCAL_FILE      : 'Local : File',
            SCESymbol.ST_LOCAL_COMMON    : 'Local : Common',
            SCESymbol.ST_LOCAL_TLS       : 'Local : TLS',
            SCESymbol.ST_GLOBAL_NONE     : 'Global : None',
            SCESymbol.ST_GLOBAL_OBJECT   : 'Global : Object',
            SCESymbol.ST_GLOBAL_FUNCTION : 'Global : Function',
            SCESymbol.ST_GLOBAL_SECTION  : 'Global : Section',
            SCESymbol.ST_GLOBAL_FILE     : 'Global : File',
            SCESymbol.ST_GLOBAL_COMMON   : 'Global : Common',
            SCESymbol.ST_GLOBAL_TLS      : 'Global : TLS',
            SCESymbol.ST_WEAK_NONE       : 'Weak : None',
            SCESymbol.ST_WEAK_OBJECT     : 'Weak : Object',
            SCESymbol.ST_WEAK_FUNCTION   : 'Weak : Function',
            SCESymbol.ST_WEAK_SECTION    : 'Weak : Section',
            SCESymbol.ST_WEAK_FILE       : 'Weak : File',
            SCESymbol.ST_WEAK_COMMON     : 'Weak : Common',
            SCESymbol.ST_WEAK_TLS        : 'Weak : TLS',
        }.get(self.INFO, 'Missing Symbol Information!!!')
    
    def process(self, symbols):
    
        if self.NAME != 0:
            symbols[self.NAME] = 0
        
        return self.info()
    
    def resolve(self, address, nids, symbol):
    
        # Resolve the NID...
        try:
            self.bv.set_comment_at(self.VALUE, 'NID: ' + symbol)
        except:
            pass
        function = nids.get(symbol[:11], symbol)
        
        if self.VALUE > 0:
            self.bv.add_function(self.VALUE).name = function
            self.bv.set_comment_at(address, '%s | %s' % (function, self.info()))

class Relocation:

    __slots__ = ('OFFSET', 'INDEX', 'INFO', 'ADDEND', 'bv')
    
    # PS4 (X86_64) Relocation Codes (40)
    (R_X86_64_NONE, R_X86_64_64, R_X86_64_PC32, R_X86_64_GOT32,
    R_X86_64_PLT32, R_X86_64_COPY, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT,
    R_X86_64_RELATIVE, R_X86_64_GOTPCREL, R_X86_64_32, R_X86_64_32S,
    R_X86_64_16, R_X86_64_PC16, R_X86_64_8, R_X86_64_PC8, R_X86_64_DTPMOD64,
    R_X86_64_DTPOFF64, R_X86_64_TPOFF64, R_X86_64_TLSGD, R_X86_64_TLSLD,
    R_X86_64_DTPOFF32, R_X86_64_GOTTPOFF, R_X86_64_TPOFF32, R_X86_64_PC64,
    R_X86_64_GOTOFF64, R_X86_64_GOTPC32, R_X86_64_GOT64, R_X86_64_GOTPCREL64,
    R_X86_64_GOTPC64, R_X86_64_GOTPLT64, R_X86_64_PLTOFF64, R_X86_64_SIZE32,
    R_X86_64_SIZE64, R_X86_64_GOTPC32_TLSDESC, R_X86_64_TLSDESC_CALL, R_X86_64_TLSDESC,
    R_X86_64_IRELATIVE, R_X86_64_RELATIVE64) = range(0x27)
    R_X86_64_ORBIS_GOTPCREL_LOAD             = 0x28 
    
    def __init__(self, bv):
        f = bv.reader
        self.bv = bv
        self.OFFSET = struct.unpack('<Q', f.read(8))[0]
        self.INFO   = struct.unpack('<Q', f.read(8))[0]
        self.ADDEND = struct.unpack('<Q', f.read(8))[0]
    
    def type(self):
    
        return {
            Relocation.R_X86_64_NONE                : 'R_X86_64_NONE',
            Relocation.R_X86_64_64                  : 'R_X86_64_64',
            Relocation.R_X86_64_PC32                : 'R_X86_64_PC32',
            Relocation.R_X86_64_GOT32               : 'R_X86_64_GOT32',
            Relocation.R_X86_64_PLT32               : 'R_X86_64_PLT32',
            Relocation.R_X86_64_COPY                : 'R_X86_64_COPY',
            Relocation.R_X86_64_GLOB_DAT            : 'R_X86_64_GLOB_DAT',
            Relocation.R_X86_64_JUMP_SLOT           : 'R_X86_64_JUMP_SLOT',
            Relocation.R_X86_64_RELATIVE            : 'R_X86_64_RELATIVE',
            Relocation.R_X86_64_GOTPCREL            : 'R_X86_64_GOTPCREL',
            Relocation.R_X86_64_32                  : 'R_X86_64_32',
            Relocation.R_X86_64_32S                 : 'R_X86_64_32S',
            Relocation.R_X86_64_16                  : 'R_X86_64_16',
            Relocation.R_X86_64_PC16                : 'R_X86_64_PC16',
            Relocation.R_X86_64_8                   : 'R_X86_64_8',
            Relocation.R_X86_64_PC8                 : 'R_X86_64_PC8',
            Relocation.R_X86_64_DTPMOD64            : 'R_X86_64_DTPMOD64',
            Relocation.R_X86_64_DTPOFF64            : 'R_X86_64_DTPOFF64',
            Relocation.R_X86_64_TPOFF64             : 'R_X86_64_TPOFF64',
            Relocation.R_X86_64_TLSGD               : 'R_X86_64_TLSGD',
            Relocation.R_X86_64_TLSLD               : 'R_X86_64_TLSLD',
            Relocation.R_X86_64_DTPOFF32            : 'R_X86_64_DTPOFF32',
            Relocation.R_X86_64_GOTTPOFF            : 'R_X86_64_GOTTPOFF',
            Relocation.R_X86_64_TPOFF32             : 'R_X86_64_TPOFF32',
            Relocation.R_X86_64_PC64                : 'R_X86_64_PC64',
            Relocation.R_X86_64_GOTOFF64            : 'R_X86_64_GOTOFF64',
            Relocation.R_X86_64_GOTPC32             : 'R_X86_64_GOTPC32',
            Relocation.R_X86_64_GOT64               : 'R_X86_64_GOT64',
            Relocation.R_X86_64_GOTPCREL64          : 'R_X86_64_GOTPCREL64',
            Relocation.R_X86_64_GOTPC64             : 'R_X86_64_GOTPC64',
            Relocation.R_X86_64_GOTPLT64            : 'R_X86_64_GOTPLT64',
            Relocation.R_X86_64_PLTOFF64            : 'R_X86_64_PLTOFF64',
            Relocation.R_X86_64_SIZE32              : 'R_X86_64_SIZE32',
            Relocation.R_X86_64_SIZE64              : 'R_X86_64_SIZE64',
            Relocation.R_X86_64_GOTPC32_TLSDESC     : 'R_X86_64_GOTPC32_TLSDESC',
            Relocation.R_X86_64_TLSDESC_CALL        : 'R_X86_64_TLSDESC_CALL',
            Relocation.R_X86_64_TLSDESC             : 'R_X86_64_TLSDESC',
            Relocation.R_X86_64_IRELATIVE           : 'R_X86_64_IRELATIVE',
            Relocation.R_X86_64_RELATIVE64          : 'R_X86_64_RELATIVE64',
            Relocation.R_X86_64_ORBIS_GOTPCREL_LOAD : 'R_X86_64_ORBIS_GOTPCREL_LOAD',
        }.get(self.INFO, 'Missing PS4 Relocation Type!!!')
    
    def process(self, nids, symbols):
    
        if self.INFO > Relocation.R_X86_64_ORBIS_GOTPCREL_LOAD:
            self.INDEX = self.INFO >> 32
            self.INFO &= 0xFF
            
            # Symbol Value + AddEnd (S + A)
            if self.type() == 'R_X86_64_64':
                self.INDEX += self.ADDEND
            
            if self.type() != 'R_X86_64_DTPMOD64':
                symbol = next(value for key, value in enumerate(symbols) if key + 2 == self.INDEX)[1]
        
        # String (Offset) == Base + AddEnd (B + A)
        if self.type() == 'R_X86_64_RELATIVE':
            self.bv.write(self.OFFSET, self.ADDEND.to_bytes(0x8, byteorder='little'))
            self.bv.define_data_var(self.OFFSET, "int64_t")
        
        # TLS Object
        elif self.type() in ['R_X86_64_DTPMOD64', 'R_X86_64_DTPOFF64']:
            pass
            #idc.set_name(self.OFFSET, 'tls_access_struct', SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        # Object
        else:
            # Resolve the NID...
            try:
                self.bv.set_comment_at(self.OFFSET, 'NID: ' + symbol)
            except:
                pass
            object = nids.get(symbol[:11], symbol)
            self.bv.define_data_var(self.OFFSET, "int64_t", object)
        
        return self.type()
    
    def resolve(self, alphabet, nids, symbols, libraries):
    
        if self.INFO > Relocation.R_X86_64_ORBIS_GOTPCREL_LOAD:
            self.INDEX = self.INFO >> 32
            self.INFO &= 0xFF
            symbol = next(value for key, value in enumerate(symbols) if key + 2 == self.INDEX)[1]
        
        # Library
        try:
            lid1 = alphabet[symbol[12:13]]
            
            # [base64]#
            if symbol[13:14] == '#':
                library = libraries[lid1]
            
            # [base64][base64]#
            elif symbol[14:15] == '#':
                lid2 = alphabet[symbol[13:14]]
                library = libraries[lid1 + lid2]
            
            else:
                raise
        
        # Not a NID
        except:
            library = ''
        
        # Function Name (Offset) == Symbol Value + AddEnd (S + A)
        # Library Name  (Offset) == Symbol Value (S)
        real = self.bv.read_pointer(self.OFFSET)
        
        # Hacky way to determine if this is the real function...
        real -= 0x6 if 'push' in self.bv.get_disassembly(real) else 0x0
        
        # Resolve the NID...
        try:
            self.bv.set_comment_at(real, 'NID: ' + symbol)
        except:
            pass
        function = str(nids.get(symbol[:11], symbol))
        
        try:
            if not self.bv.get_function_at(real):
                self.bv.create_user_function(real)
            demangled_name = demangle_generic(self.bv.arch, function)
            func = self.bv.get_function_at(real)
            func.type = Type.function(Type.void(), [], variable_arguments=True)
            func.name = function if demangled_name[0] is None else demangled_name[1][0]
            self.bv.define_auto_symbol(Symbol(SymbolType.ImportAddressSymbol, self.OFFSET, '__imp_' + function))
        except:
            pass
        
        return self.type()

class Dynamic:
    
    __slots__ = ('TAG', 'VALUE', 'ID', 'VERSION_MAJOR', 'VERSION_MINOR', 'INDEX', 'bv')
    
    # Dynamic Tags
    (DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB,
    DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI,
    DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL, DT_RELSZ, DT_RELENT, DT_PLTREL,
    DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW, DT_INIT_ARRAY, DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS, DT_ENCODING, DT_PREINIT_ARRAY,
    DT_PREINIT_ARRAYSZ)         = range(0x22)
    DT_SCE_IDTABENTSZ           = 0x61000005
    DT_SCE_FINGERPRINT          = 0x61000007
    DT_SCE_ORIGINAL_FILENAME    = 0x61000009
    DT_SCE_MODULE_INFO          = 0x6100000D
    DT_SCE_NEEDED_MODULE        = 0x6100000F
    DT_SCE_MODULE_ATTR          = 0x61000011
    DT_SCE_EXPORT_LIB           = 0x61000013
    DT_SCE_IMPORT_LIB           = 0x61000015
    DT_SCE_EXPORT_LIB_ATTR      = 0x61000017
    DT_SCE_IMPORT_LIB_ATTR      = 0x61000019
    DT_SCE_STUB_MODULE_NAME     = 0x6100001D
    DT_SCE_STUB_MODULE_VERSION  = 0x6100001F
    DT_SCE_STUB_LIBRARY_NAME    = 0x61000021
    DT_SCE_STUB_LIBRARY_VERSION = 0x61000023
    DT_SCE_HASH                 = 0x61000025
    DT_SCE_PLTGOT               = 0x61000027
    DT_SCE_JMPREL               = 0x61000029
    DT_SCE_PLTREL               = 0x6100002B
    DT_SCE_PLTRELSZ             = 0x6100002D
    DT_SCE_RELA                 = 0x6100002F
    DT_SCE_RELASZ               = 0x61000031
    DT_SCE_RELAENT              = 0x61000033
    DT_SCE_STRTAB               = 0x61000035
    DT_SCE_STRSZ                = 0x61000037
    DT_SCE_SYMTAB               = 0x61000039
    DT_SCE_SYMENT               = 0x6100003B
    DT_SCE_HASHSZ               = 0x6100003D
    DT_SCE_SYMTABSZ             = 0x6100003F
    DT_SCE_HIOS                 = 0x6FFFF000
    DT_GNU_HASH                 = 0x6FFFFEF5
    DT_VERSYM                   = 0x6FFFFFF0
    DT_RELACOUNT                = 0x6FFFFFF9
    DT_RELCOUNT                 = 0x6FFFFFFA
    DT_FLAGS_1                  = 0x6FFFFFFB
    DT_VERDEF                   = 0x6FFFFFFC
    DT_VERDEFNUM                = 0x6FFFFFFD

    def __init__(self, bv):
        f = bv.reader
        self.bv = bv
        self.TAG   = struct.unpack('<Q', f.read(8))[0]
        self.VALUE = struct.unpack('<Q', f.read(8))[0]
    
    def tag(self):
    
        return {
            Dynamic.DT_NULL                     : 'DT_NULL',
            Dynamic.DT_NEEDED                   : 'DT_NEEDED',
            Dynamic.DT_PLTRELSZ                 : 'DT_PLTRELSZ',
            Dynamic.DT_PLTGOT                   : 'DT_PLTGOT',
            Dynamic.DT_HASH                     : 'DT_HASH',
            Dynamic.DT_STRTAB                   : 'DT_STRTAB',
            Dynamic.DT_SYMTAB                   : 'DT_SYMTAB',
            Dynamic.DT_RELA                     : 'DT_RELA',
            Dynamic.DT_RELASZ                   : 'DT_RELASZ',
            Dynamic.DT_RELAENT                  : 'DT_RELAENT',
            Dynamic.DT_STRSZ                    : 'DT_STRSZ',
            Dynamic.DT_SYMENT                   : 'DT_SYMENT',
            Dynamic.DT_INIT                     : 'DT_INIT',
            Dynamic.DT_FINI                     : 'DT_FINI',
            Dynamic.DT_SONAME                   : 'DT_SONAME',
            Dynamic.DT_RPATH                    : 'DT_RPATH',
            Dynamic.DT_SYMBOLIC                 : 'DT_SYMBOLIC',
            Dynamic.DT_REL                      : 'DT_REL',
            Dynamic.DT_RELSZ                    : 'DT_RELSZ',
            Dynamic.DT_RELENT                   : 'DT_RELENT',
            Dynamic.DT_PLTREL                   : 'DT_PLTREL',
            Dynamic.DT_DEBUG                    : 'DT_DEBUG',
            Dynamic.DT_TEXTREL                  : 'DT_TEXTREL',
            Dynamic.DT_JMPREL                   : 'DT_JMPREL',
            Dynamic.DT_BIND_NOW                 : 'DT_BIND_NOW',
            Dynamic.DT_INIT_ARRAY               : 'DT_INIT_ARRAY',
            Dynamic.DT_FINI_ARRAY               : 'DT_FINI_ARRAY',
            Dynamic.DT_INIT_ARRAYSZ             : 'DT_INIT_ARRAYSZ',
            Dynamic.DT_FINI_ARRAYSZ             : 'DT_FINI_ARRAYSZ',
            Dynamic.DT_RUNPATH                  : 'DT_RUN_PATH',
            Dynamic.DT_FLAGS                    : 'DT_FLAGS',
            Dynamic.DT_ENCODING                 : 'DT_ENCODING',
            Dynamic.DT_PREINIT_ARRAY            : 'DT_PREINIT_ARRAY',
            Dynamic.DT_PREINIT_ARRAYSZ          : 'DT_PREINIT_ARRAYSZ',
            Dynamic.DT_SCE_IDTABENTSZ           : 'DT_SCE_IDTABENTSZ',
            Dynamic.DT_SCE_FINGERPRINT          : 'DT_SCE_FINGERPRINT',
            Dynamic.DT_SCE_ORIGINAL_FILENAME    : 'DT_SCE_ORIGINAL_FILENAME',
            Dynamic.DT_SCE_MODULE_INFO          : 'DT_SCE_MODULE_INFO',
            Dynamic.DT_SCE_NEEDED_MODULE        : 'DT_SCE_NEEDED_MODULE',
            Dynamic.DT_SCE_MODULE_ATTR          : 'DT_SCE_MODULE_ATTR',
            Dynamic.DT_SCE_EXPORT_LIB           : 'DT_SCE_EXPORT_LIB',
            Dynamic.DT_SCE_IMPORT_LIB           : 'DT_SCE_IMPORT_LIB',
            Dynamic.DT_SCE_EXPORT_LIB_ATTR      : 'DT_SCE_EXPORT_LIB_ATTR',
            Dynamic.DT_SCE_IMPORT_LIB_ATTR      : 'DT_SCE_IMPORT_LIB_ATTR',
            Dynamic.DT_SCE_STUB_MODULE_NAME     : 'DT_SCE_STUB_MODULE_NAME',
            Dynamic.DT_SCE_STUB_MODULE_VERSION  : 'DT_SCE_STUB_MODULE_VERSION',
            Dynamic.DT_SCE_STUB_LIBRARY_NAME    : 'DT_SCE_STUB_LIBRARY_NAME',
            Dynamic.DT_SCE_STUB_LIBRARY_VERSION : 'DT_SCE_STUB_LIBRARY_VERSION',
            Dynamic.DT_SCE_HASH                 : 'DT_SCE_HASH',
            Dynamic.DT_SCE_PLTGOT               : 'DT_SCE_PLTGOT',
            Dynamic.DT_SCE_JMPREL               : 'DT_SCE_JMPREL',
            Dynamic.DT_SCE_PLTREL               : 'DT_SCE_PLTREL',
            Dynamic.DT_SCE_PLTRELSZ             : 'DT_SCE_PLTRELSZ',
            Dynamic.DT_SCE_RELA                 : 'DT_SCE_RELA',
            Dynamic.DT_SCE_RELASZ               : 'DT_SCE_RELASZ',
            Dynamic.DT_SCE_RELAENT              : 'DT_SCE_RELAENT',
            Dynamic.DT_SCE_STRTAB               : 'DT_SCE_STRTAB',
            Dynamic.DT_SCE_STRSZ                : 'DT_SCE_STRSZ',
            Dynamic.DT_SCE_SYMTAB               : 'DT_SCE_SYMTAB',
            Dynamic.DT_SCE_SYMENT               : 'DT_SCE_SYMENT',
            Dynamic.DT_SCE_HASHSZ               : 'DT_SCE_HASHSZ',
            Dynamic.DT_SCE_SYMTABSZ             : 'DT_SCE_SYMTABSZ',
            Dynamic.DT_SCE_HIOS                 : 'DT_SCE_HIOS',
            Dynamic.DT_GNU_HASH                 : 'DT_GNU_HASH',
            Dynamic.DT_VERSYM                   : 'DT_VERSYM',
            Dynamic.DT_RELACOUNT                : 'DT_RELACOUNT',
            Dynamic.DT_RELCOUNT                 : 'DT_RELCOUNT',
            Dynamic.DT_FLAGS_1                  : 'DT_FLAGS_1',
            Dynamic.DT_VERDEF                   : 'DT_VERDEF',
            Dynamic.DT_VERDEFNUM                : 'DT_VERDEFNUM',
        }.get(self.TAG, 'Missing Dynamic Tag!!!')
    
    def lib_attribute(self):
    
        return {
            0x1  : 'AUTO_EXPORT',
            0x2  : 'WEAK_EXPORT',
            0x8  : 'LOOSE_IMPORT',
            0x9  : 'AUTO_EXPORT|LOOSE_IMPORT',
            0x10 : 'WEAK_EXPORT|LOOSE_IMPORT',
        }.get(self.INDEX, 'Missing Library Attribute!!!')
    
    def mod_attribute(self):
    
        return {
            0x0  : 'NONE',
            0x1  : 'SCE_CANT_STOP',
            0x2  : 'SCE_EXCLUSIVE_LOAD',
            0x4  : 'SCE_EXCLUSIVE_START',
            0x8  : 'SCE_CAN_RESTART',
            0x10 : 'SCE_CAN_RELOCATE',
            0x20 : 'SCE_CANT_SHARE',
        }.get(self.INDEX, 'Missing Module Attribute!!!')
    
    def comment(self, address, stubs, modules, libraries):
    
        if self.TAG in [Dynamic.DT_NEEDED, Dynamic.DT_SONAME]:
            return '%s | %s' % (self.tag(), str(stubs[self.VALUE]))
        elif self.TAG == Dynamic.DT_SCE_HASH:
            address += Dynamic.HASHTAB
            self.bv.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, ".hash"))
            self.bv.define_data_var(address, "int", ".hash")
            return '%s | %#x' % (self.tag(), address)
        elif self.TAG == Dynamic.DT_SCE_STRTAB:
            address += Dynamic.STRTAB
            self.bv.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, ".dynstr"))
            self.bv.define_data_var(address, "int", ".dynstr")
            return '%s | %#x' % (self.tag(), address)
        elif self.TAG == Dynamic.DT_SCE_SYMTAB:
            address += Dynamic.SYMTAB
            self.bv.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, ".dynsym"))
            self.bv.define_data_var(address, "int", ".dynsym")
            return '%s | %#x' % (self.tag(), address)
        elif self.TAG == Dynamic.DT_SCE_JMPREL:
            return '%s | %#x' % (self.tag(), address + Dynamic.JMPTAB)
        elif self.TAG == Dynamic.DT_SCE_RELA:
            return '%s | %#x' % (self.tag(), address + Dynamic.RELATAB)
        elif self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_IMPORT_LIB,
                          Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB,
                          Dynamic.DT_SCE_EXPORT_LIB_ATTR, Dynamic.DT_SCE_MODULE_INFO,
                          Dynamic.DT_SCE_MODULE_ATTR, Dynamic.DT_SCE_FINGERPRINT,
                          Dynamic.DT_SCE_ORIGINAL_FILENAME]:
            self.ID             = self.VALUE >> 48
            self.VERSION_MINOR  = (self.VALUE >> 40) & 0xF
            self.VERSION_MAJOR  = (self.VALUE >> 32) & 0xF
            self.INDEX          = self.VALUE & 0xFFF
            
            if self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_MODULE_INFO]:
                return '%s | MID:%#x Version:%i.%i Name:%s' % \
                       (self.tag(), self.ID, self.VERSION_MAJOR, self.VERSION_MINOR, str(modules[self.INDEX]))
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB, Dynamic.DT_SCE_EXPORT_LIB]:
                return '%s | LID:%#x Version:%i Name:%s' % \
                       (self.tag(), self.ID, self.VERSION_MAJOR, str(libraries[self.INDEX]))
            elif self.TAG == Dynamic.DT_SCE_MODULE_ATTR:
                return '%s | %s' % (self.tag(), self.mod_attribute())
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB_ATTR]:
                return '%s | LID:%#x Attributes:%s' % \
                       (self.tag(), self.ID, self.lib_attribute())
            elif self.TAG == Dynamic.DT_SCE_FINGERPRINT:
                return '%s | %s' % (self.tag(), Dynamic.FINGERPRINT)
            elif self.TAG == Dynamic.DT_SCE_ORIGINAL_FILENAME:
                return '%s | %s' % (self.tag(), str(stubs[self.VALUE]))
        
        return '%s | %#x' % (self.tag(), self.VALUE)
    
    def process(self, stubs, modules, libraries):
    
        if self.TAG == Dynamic.DT_INIT:
            Dynamic.INIT = self.VALUE
            if Dynamic.INIT > 0:
                self.bv.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, Dynamic.INIT, ".init"))
                self.bv.add_function(Dynamic.INIT).name = ".init"
        elif self.TAG == Dynamic.DT_FINI:
            Dynamic.FINI = self.VALUE
            if Dynamic.FINI > 0:
                self.bv.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, Dynamic.FINI, ".fini"))
                self.bv.add_function(Dynamic.FINI).name = ".fini"
        elif self.TAG in [Dynamic.DT_NEEDED, Dynamic.DT_SONAME]:
            stubs[self.VALUE] = 0
        elif self.TAG == Dynamic.DT_SCE_STRTAB:
            Dynamic.STRTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_STRSZ:
            Dynamic.STRTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_SYMTAB:
            Dynamic.SYMTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_SYMTABSZ:
            Dynamic.SYMTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_JMPREL:
            Dynamic.JMPTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_PLTRELSZ:
            Dynamic.JMPTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_PLTREL:
            if self.VALUE == 0x7:
                return '%s | %#x | DT_RELA' % (self.tag(), self.VALUE)
        elif self.TAG == Dynamic.DT_SCE_RELA:
            Dynamic.RELATAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_RELASZ:
            Dynamic.RELATABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_HASH:
            Dynamic.HASHTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_HASHSZ:
            Dynamic.HASHTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_PLTGOT:
            Dynamic.GOT = self.VALUE
            self.bv.define_auto_symbol(Symbol(SymbolType.DataSymbol, Dynamic.GOT, ".got.plt"))
            self.bv.define_data_var(Dynamic.GOT, "int", ".got.plt")
        elif self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_IMPORT_LIB,
                          Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB,
                          Dynamic.DT_SCE_EXPORT_LIB_ATTR, Dynamic.DT_SCE_MODULE_INFO,
                          Dynamic.DT_SCE_MODULE_ATTR, Dynamic.DT_SCE_FINGERPRINT,
                          Dynamic.DT_SCE_ORIGINAL_FILENAME]:
            self.ID             = self.VALUE >> 48
            self.VERSION_MINOR  = (self.VALUE >> 40) & 0xF
            self.VERSION_MAJOR  = (self.VALUE >> 32) & 0xF
            self.INDEX          = self.VALUE & 0xFFF
            
            if self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_MODULE_INFO]:
                modules[self.INDEX] = 0
                return '%s | MID:%#x Version:%i.%i | %#x' % \
                       (self.tag(), self.ID, self.VERSION_MAJOR, self.VERSION_MINOR, self.INDEX)
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB, Dynamic.DT_SCE_EXPORT_LIB]:
                libraries[self.INDEX] = self.ID
                return '%s | LID:%#x Version:%i | %#x' % \
                       (self.tag(), self.ID, self.VERSION_MAJOR, self.INDEX)
            elif self.TAG == Dynamic.DT_SCE_MODULE_ATTR:
                return '%s | %s' % (self.tag(), self.mod_attribute())
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB_ATTR]:
                return '%s | LID:%#x Attributes:%s' % \
                       (self.tag(), self.ID, self.lib_attribute())
            elif self.TAG == Dynamic.DT_SCE_FINGERPRINT:
                Dynamic.FINGERPRINT = self.VALUE
            elif self.TAG == Dynamic.DT_SCE_ORIGINAL_FILENAME:
                stubs[self.INDEX] = 0
        
        return '%s | %#x' % (self.tag(), self.VALUE)

class Segment:
    PT_NULL                = 0x0
    PT_LOAD                = 0x1
    PT_DYNAMIC             = 0x2
    PT_INTERP              = 0x3
    PT_NOTE                = 0x4
    PT_SHLIB               = 0x5
    PT_PHDR                = 0x6
    PT_TLS                 = 0x7
    PT_NUM                 = 0x8
    PT_SCE_DYNLIBDATA      = 0x61000000
    PT_SCE_PROCPARAM       = 0x61000001
    PT_SCE_MODULEPARAM     = 0x61000002
    PT_SCE_RELRO           = 0x61000010
    PT_GNU_EH_FRAME        = 0x6474E550
    PT_GNU_STACK           = 0x6474E551
    PT_SCE_COMMENT         = 0x6FFFFF00
    PT_SCE_LIBVERSION      = 0x6FFFFF01
    PT_HIOS                = 0x6FFFFFFF
    PT_LOPROC              = 0x70000000
    PT_SCE_SEGSYM          = 0x700000A8
    PT_HIPROC              = 0x7FFFFFFF
    
    # Segment Alignments
    AL_NONE                = 0x0
    AL_BYTE                = 0x1
    AL_WORD                = 0x2
    AL_DWORD               = 0x4
    AL_QWORD               = 0x8
    AL_PARA                = 0x10
    AL_4K                  = 0x4000

    # Flags
    SEGPERM_EXEC           = 0x1
    SEGPERM_READ           = 0x4

    def __init__(self, f):
        self.TYPE      = struct.unpack('<I', f.read(4))[0]
        self.FLAGS     = struct.unpack('<I', f.read(4))[0]
        self.OFFSET    = struct.unpack('<Q', f.read(8))[0]
        self.MEM_ADDR  = struct.unpack('<Q', f.read(8))[0]
        self.FILE_ADDR = struct.unpack('<Q', f.read(8))[0]
        self.FILE_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.MEM_SIZE  = struct.unpack('<Q', f.read(8))[0]
        self.ALIGNMENT = struct.unpack('<Q', f.read(8))[0]

    def flags(self):
        return self.FLAGS & 0xF
    
    def name(self):
    
        return {
            Segment.PT_NULL            : 'NULL',
            Segment.PT_LOAD            : 'CODE' if self.flags() == (Segment.SEGPERM_EXEC | Segment.SEGPERM_READ) else 'DATA',
            Segment.PT_DYNAMIC         : 'DYNAMIC',
            Segment.PT_INTERP          : 'INTERP',
            Segment.PT_NOTE            : 'NOTE',
            Segment.PT_SHLIB           : 'SHLIB',
            Segment.PT_PHDR            : 'PHDR',
            Segment.PT_TLS             : 'TLS',
            Segment.PT_NUM             : 'NUM',
            Segment.PT_SCE_DYNLIBDATA  : 'SCE_DYNLIBDATA',
            Segment.PT_SCE_PROCPARAM   : 'SCE_PROCPARAM',
            Segment.PT_SCE_MODULEPARAM : 'SCE_MODULEPARAM',
            Segment.PT_SCE_RELRO       : 'SCE_RELRO',
            Segment.PT_GNU_EH_FRAME    : 'GNU_EH_FRAME',
            Segment.PT_GNU_STACK       : 'GNU_STACK',
            Segment.PT_SCE_COMMENT     : 'SCE_COMMENT',
            Segment.PT_SCE_LIBVERSION  : 'SCE_LIBVERSION',
        }.get(self.TYPE, 'UNK')
    
    def type(self):
        return {
            Segment.PT_LOAD            : SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable if self.flags() == (Segment.SEGPERM_EXEC | Segment.SEGPERM_READ) else SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_DYNAMIC         : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_INTERP          : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_NOTE            : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_PHDR            : SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable,
            Segment.PT_TLS             : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_SCE_DYNLIBDATA  : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_SCE_PROCPARAM   : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_SCE_MODULEPARAM : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_SCE_RELRO       : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_GNU_EH_FRAME    : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
            Segment.PT_GNU_STACK       : SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable,
        }.get(self.TYPE, SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData)

    def section_type(self):
        return {
            Segment.PT_LOAD            : SectionSemantics.ReadOnlyCodeSectionSemantics if self.flags() == (Segment.SEGPERM_EXEC | Segment.SEGPERM_READ) else SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_DYNAMIC         : SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_INTERP          : SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_NOTE            : SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_PHDR            : SectionSemantics.ReadOnlyCodeSectionSemantics,
            Segment.PT_TLS             : SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_SCE_DYNLIBDATA  : SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_SCE_PROCPARAM   : SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_SCE_MODULEPARAM : SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_SCE_RELRO       : SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_GNU_EH_FRAME    : SectionSemantics.ReadWriteDataSectionSemantics,
            Segment.PT_GNU_STACK       : SectionSemantics.ReadWriteDataSectionSemantics,
        }.get(self.TYPE, SectionSemantics.ReadWriteDataSectionSemantics)

    def struct(self, members, location = 0x0):
        entry = TypeBuilder.structure([])
        
        for (member, comment, size) in members:
            entry.append(Type.int(size), member)

            location += size
        
        return entry

class Section:
    
    __slots__ = ('NAME', 'TYPE', 'FLAGS', 'MEM_ADDR',
                 'OFFSET', 'FILE_SIZE', 'LINK', 'INFO',
                 'ALIGNMENT', 'FSE_SIZE')
    
    def __init__(self, f):
        self.NAME      = struct.unpack('<I', f.read(4))[0]
        self.TYPE      = struct.unpack('<I', f.read(4))[0]
        self.FLAGS     = struct.unpack('<Q', f.read(8))[0]
        self.MEM_ADDR  = struct.unpack('<Q', f.read(8))[0]
        self.OFFSET    = struct.unpack('<Q', f.read(8))[0]
        self.FILE_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.LINK      = struct.unpack('<I', f.read(4))[0]
        self.INFO      = struct.unpack('<I', f.read(4))[0]
        self.ALIGNMENT = struct.unpack('<Q', f.read(8))[0]
        self.FSE_SIZE  = struct.unpack('<Q', f.read(8))[0]