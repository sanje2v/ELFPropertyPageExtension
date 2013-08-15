###############################################################
## Name: ELF-property-page.py
## Version: 1.0 Alpha release
## Installation Path: ~/.local/share/nautilus-pthon/extensions
## Written By: Sanjeev Sharma
## License: GNU Freeware
## Feel free to modify but ofcourse the usual 'notify and mention
##	 the original author' applies
## Email: swtbase at yahoo.com
###############################################################

import urllib
import struct

from gi.repository import Nautilus, Gtk, Gdk, GObject
from struct import *

# Global attributes
SUPPORTED_FORMATS = ['application/x-executable', 'application/x-sharedlib']
GENERIC_COLUMN_NAMES = ['Field', 'Data', 'Annotation']
LITTLE_ENDIAN = ARCH_32BIT = 1
BIG_ENDIAN = ARCH_64BIT = 2
DECIMAL = 1
HEXADECIMAL = 2

SIZE_OF_ELFID = 16
SIZE_OF_BYTE = 1
SIZE_OF_WORD = 2
SIZE_OF_DWORD = 4
SIZE_OF_QWORD = 8
SIZE_OF_XWORD = SIZE_OF_DWORD	# May change according to target file arch

GTK_MOUSE_LBUTTON = 1
GTK_MOUSE_RBUTTON = 3

# Global functions
def toHex(data):
	return '0x{0:02x}'.format(data)

# Main class ELFPropertyPage
class ELFPropertyPage(GObject.GObject, Nautilus.PropertyPageProvider):
	def __init__(self):
		pass

	def __del__(self):
		try:
			self.ELFfile.close()

		except:
			pass

		print "Bye"


	################# MakeBYTE() #################
	def MakeBYTE(self, data):
		return ord(data)


	################# MakeWORD() #################
	def MakeWORD(self, data):
		return struct.unpack(('<' if self.ELFendian == LITTLE_ENDIAN else '>') + 'H', data)[0]


	################# MakeDWORD() ################
	def MakeDWORD(self, data):
		return struct.unpack(('<' if self.ELFendian == LITTLE_ENDIAN else '>') + 'I', data)[0]


	################# MakeQWORD() ################
	def MakeQWORD(self, data):
		return struct.unpack(('<' if self.ELFendian == LITTLE_ENDIAN else '>') + 'Q', data)[0]


	################# MakeXWORD() ################
	def MakeXWORD(self, data):
		return self.MakeDWORD(data) if self.ELFarch == ARCH_32BIT else self.MakeQWORD(data)


	############### DecodeBYTEs() ################
	def DecodeBYTEs(self, data, radix = DECIMAL):
		retval = str('0x')
		for i in range(len(data)):
			retval += (str(ord(data[i])) if radix == DECIMAL else toHex(ord(data[i])))[2:]

		return retval.strip()


	################ DecodeWORD() ################
	def DecodeWORD(self, data, radix = DECIMAL):
		return str(self.MakeWORD(data)) if radix == DECIMAL else toHex(self.MakeWORD(data))


	############### DecodeDWORD() ################
	def DecodeDWORD(self, data, radix = DECIMAL):
		return str(self.MakeDWORD(data)) if radix == DECIMAL else toHex(self.MakeDWORD(data))


	################ DecodeQWORD() ###############
	def DecodeQWORD(self, data, radix = DECIMAL):
		return str(self.MakeQWORD(data)) if radix == DECIMAL else toHex(self.MakeQWORD(data))


	################ DecodeXWORD() ################
	def DecodeXWORD(self, data, radix = DECIMAL):
		return self.DecodeDWORD(data, radix) if self.ELFarch == ARCH_32BIT else self.DecodeQWORD(data, radix)


	################# FormatSize() ################
	def FormatSize(self, size):
		temp = float(self.MakeWORD(size) if len(size) == 2 else self.MakeXWORD(size))
		i = int(0)

		while temp >= float(1024):
			temp /= 1024
			i += 1
			if i == 3:
				break

		temp = round(temp, 2)

		if i == 1:
			return str(temp) + ' KB'
		elif i == 2:
			return str(temp) + ' MB'
		elif i == 3:
			return str(temp) + ' GB'
		else:
			return 'byte(s)'


	################# ELFfile_peek() #################
	def ELFfile_peek(self, size):
		oldpos = self.ELFfile.tell()
		data = self.ELFfile.read(size)
		self.ELFfile.seek(oldpos, 0)
		return data


	################# ELFfile_peekAt() #################
	def ELFfile_peekAt(self, pos, size):
		oldpos = self.ELFfile.tell()
		self.ELFfile.seek(pos, 0)
		data = self.ELFfile.read(size)
		self.ELFfile.seek(oldpos, 0)
		return data


	################# IsValidELFSignature() #################
	def IsValidELFSignature(self, data):
		return self.MakeBYTE(data[0]) == 0x7F and data[1:4] == 'ELF'


	################# DecodeELFSignature() #################
	def DecodeELFSignature(self, data):
		# Check signature
		if self.IsValidELFSignature(data):
			retval = 'ELF Signature Found'
		else:
			return 'Invalid Signature'

		# Find class
		if self.MakeBYTE(data[4]) == ARCH_32BIT:
			retval += ', 32-bit objects'
		elif self.MakeBYTE(data[4]) == ARCH_64BIT:
			retval += ', 64-bit objects'
		else:
			retval += ', Unknown/Invalid class'

		# Data endian
		if self.MakeBYTE(data[5]) == LITTLE_ENDIAN:
			retval += ', Little endian'
		elif self.MakeBYTE(data[5]) == BIG_ENDIAN:
			retval += ', Big endian'
		else:
			retval += ', Unknown data encoding'

		# Read version
		if self.MakeBYTE(data[6]) == 1:
			retval += ', Current version'
		else:
			retval += ', Unknown/Invalid version'

		# Read OS and ABI identifiers
		if self.MakeBYTE(data[7]) == 0:
			retval += ', System V ABI'
		elif self.MakeBYTE(data[7]) == 1:
			retval += ', HP-UX OS'
		elif self.MakeBYTE(data[7]) == 255:
			retval += ', Standalone (embedded) application'
		else:
			retval += ', Unknown/Invalid OS ID'

		# Read ABI version
		if self.MakeBYTE(data[7]) == 0:
			if self.MakeBYTE(data[8]) == 0:
				retval += ', ABI v3'
		else:
				retval += ', ABI v' + str(self.MakeBYTE(data[8]))

		return retval


	################# GetFileType() #################
	def GetFileType(self, data):
		FILE_TYPE = [(0, 'No file type'), (1, 'Relocatable file'), (2, 'Executable file'), (3, 'Shared object file'), (4, 'Core file'), (0xff00, 'Processor specific low proc, Reserved'), (0xffff, 'Processor specific high proc, Reserved')]

		for i in range(len(FILE_TYPE)):
			if FILE_TYPE[i][0] == self.MakeWORD(data):
				return FILE_TYPE[i][1]

		return 'Unknown/Invalid file type'


	################# GetMachineType() #################
	def GetMachineType(self, data):
		MACHINE_INFORMATION = [(0, 'No machine'), (1, 'AT&T WE 32100'), (2, 'Sun SPARC'), (3, 'Intel 80386'), (4, 'Motorola 68000'), (5, 'Motorola 88000'), (6, 'Intel 80486'), (7, 'Intel 80860'), (8, 'MIPS RS3000 Big-Endian'), (9, 'IBM System/370 Processor'), (10, 'MIPS PS3000 Little-Endian'), (11, 'RS6000'), (15, 'PS-RISC'), (16, 'nCUBE'), (17, 'Fujitsu VPP500'), (18, 'Sun SPARC 32+'), (19, 'Intel 80960'), (20, 'PowerPC'), (21, '64-bit PowerPC'), (22, 'IBM System/390 Processor'), (36, 'NEX V800'), (37, 'Fujitsu FR20'), (38, 'TRW RH-32'), (39, 'Motorola RCE'), (40, 'Advanced RISC Marchines ARM'), (41, 'Digital Alpha'), (42, 'Hitachi SH'), (43, 'Sun SPARC V9 (64-bit)'), (44, 'Siemens Tricore embedded processor'), (45, 'Argonaut RISC Core'), (46, 'Hitachi H8/300'), (47, 'Hitachi H8/300H'), (48, 'Hitachi H8S'), (49, 'Hitachi Hitachi H8/500'), (50, 'Intel IA64'), (51, 'Stanford MIPS-X'), (52, 'Motorola ColdFire'), (53, 'Motorola M68HC12'), (54, 'Fujitsu MMA Multimedia Accelerator'), (55, 'Siemens PCP'), (56, 'Sony nCPU embedded RISC processor'), (57, 'Denso NDR1 microprocessor'), (58, 'Motorola Star Core processor'), (59, 'Toyota ME16 processor'), (60, 'STMicroelectronics ST100 processor'), (61, 'Advanced Logic Corp. TinyJ embedded processor family'), (62, 'AMDs x86-64 architecture'), (63, 'Sony DSP Processor'), (66, 'Siemens FX66 microcontroller'), (67, 'STMicroelectronics ST9+8/16 bit microcontroller'), (68, 'STMicroelectronics ST7 8-bit microcontroller'), (69, 'Motorola MC68HC16 Microcontroller'), (70, 'Motorola MC68HC11 Microcontroller'), (71, 'Motorola MC68HC08 Microcontroller'), (72, 'Motorola MC68HC05 Microcontroller'), (73, 'Silicon Graphics SVx'), (74, 'STMicroelectronics ST19 8-bit microcontroller'), (75, 'Digital VAX'), (76, 'Axis Communications 32-bit embedded processor'), (77, 'Infineon Technologies 32-bit'), (78, 'Element 14 64-bit DSP Processor'), (79, 'LSI Logic 16-bit DSP Processor'), (80, 'Donald Knuth\'s educational'), (81, 'Havard University machine-independent object files'), (82, 'SiTera Prism'), (83, 'Atmel AVR 8-bit microcontroller'), (84, 'Fujitsu FR30'), (85, 'Mitsubishi D10V'), (86, 'Mitsubishi D30V'), (87, 'NEC v850'), (88, 'Mitsubishi M32R'), (89, 'Matsushita MN10300'), (90, 'Matsushita MN10200'), (91, 'picoJava'), (92, 'OpenRISC 32-bit embedded processor'), (93, 'ARC Cores Tangent-A5'), (94, 'Tensilica Xtensa architecture')]
		
		for i in range(len(MACHINE_INFORMATION)):
			if MACHINE_INFORMATION[i][0] == self.MakeWORD(data):
				return MACHINE_INFORMATION[i][1]

		return 'Unknown/Invalid machine type'


	################# GetFileVersion() #################
	def GetFileVersion(self, data):
		return 'Current version' if self.MakeDWORD(data) == 1 else 'Invalid/Unknown version'


	################# DecodeSegmentType() #################
	def DecodeSegmentType(self, data):
		SEGMENT_TYPE = [(0, 'Null Segment'), (1, 'Loadable Segment'), (2, 'Dynamic linking tables'), (3, 'Program interpreter path name'), (4, 'Note Sections'), (5, 'Reserved'), (6, 'Program Header Table'), (7, 'Thread-Local storage template'), (0x60000000, 'OS-specific loproc'), (0x6fffffff, 'OS-specific hiproc'), (0x70000000, 'Processor specific, loproc'), (0x7fffffff, 'Processor specific, hiproc'), (0x6474e550, 'GNU Error handler frame'), (0xC474E550, 'GNU Stack')]

		for i in range(len(SEGMENT_TYPE)):
			if SEGMENT_TYPE[i][0] == self.MakeDWORD(data):
				return SEGMENT_TYPE[i][1]

		return 'Unknown/Invalid segment type'


	################# DecodeSegmentAttributes() #################
	def DecodeSegmentAttributes(self, data):
		SEGMENT_ATTRIBUTE = [(0x1, 'Executable'), (0x2, 'Writable'), (0x4, 'Readable'), (0x00FF0000, 'Reserved, Environment-specific use'), (0xFF000000, 'Reserved, Processor-specific use')]
		TEMP = str()

		for i in range(len(SEGMENT_ATTRIBUTE)):
			if SEGMENT_ATTRIBUTE[i][0] == SEGMENT_ATTRIBUTE[i][0] & self.MakeDWORD(data):
				TEMP += SEGMENT_ATTRIBUTE[i][1] + ', '

		if len(TEMP) == 0:
			return 'Unknown/Invalid segment attribute'
		else:
			return TEMP[:-2]


	################# DecodeSectionName() #################
	def DecodeSectionName(self, data):		
		if self.ELFSectionNameTableFileOffset == 0:
			return '<No string table available>'

		TEMP = str()
		oldpos = self.ELFfile.tell()

		self.ELFfile.seek(self.ELFSectionNameTableFileOffset + self.MakeDWORD(data), 0)
		while(self.ELFfile_peek(SIZE_OF_BYTE) != '\0'):
			TEMP += self.ELFfile.read(SIZE_OF_BYTE)

		self.ELFfile.seek(oldpos, 0)

		return TEMP


	################# DecodeSectionType() #################
	def DecodeSectionType(self, data):
		SECTION_TYPE = [(0, 'Unused section header'), (1, 'Program dependent information'), (2, 'Linker symbol table'), (3, 'String table'), (4, '"Rela" type relocation entries'), (5, 'Symbol hash table'), (6, 'Dynamic linking tables'), (7, 'Note information'), (8, 'Uninitialized space'), (9, '"Rel" type relocation entries'), (10, 'Reserved'), (11, 'Dynamic loader symbol table'), (0x60000000, 'Environment-specific use LOOS'), (0x6fffffff, 'Environment-specific use HIOS'), (0x70000000, 'Processor-specific use LOPROC'), (0x7fffffff, 'Processor-specific use HIPROC')]

		for i in range(len(SECTION_TYPE)):
			if SECTION_TYPE[i][0] == self.MakeDWORD(data):
				return SECTION_TYPE[i][1]

		return 'Unknown/Invalid segment type'


	################# DecodeSectionAttributes() #################
	def DecodeSectionAttributes(self, data):
		SECTION_ATTRIBUTE = [(0x1, 'Writable'), (0x2, 'Allocate in memory'), (0x4, 'Executable'), (0x0f000000, 'Environment-specific use'), (0xf0000000, 'Processor-specific use')]
		TEMP = str()

		for i in range(len(SECTION_ATTRIBUTE)):
			if SECTION_ATTRIBUTE[i][0] == SECTION_ATTRIBUTE[i][0] & self.MakeXWORD(data):
				TEMP += SECTION_ATTRIBUTE[i][1] + ', '

		if len(TEMP) == 0:
			return 'Unknown/Invalid section attibute'
		else:
			return TEMP[:-2]


	################# ELFHeaderTab_OnActivate() #################
	def ELFHeaderTab_OnActivate(self):
		# Connect signal for popup
		self.lstvwELFHeader.connect('button-release-event', self.ListView_OnButtonRelease)

		# Position file pointer
		self.ELFfile.seek(0, 0)

		# Read in data
		FIELD_DATA = [('Magic Number and File ID', self.DecodeBYTEs(self.ELFfile_peek(SIZE_OF_ELFID), HEXADECIMAL), self.DecodeELFSignature(self.ELFfile.read(SIZE_OF_ELFID))), \
('File type', self.DecodeWORD(self.ELFfile_peek(SIZE_OF_WORD), HEXADECIMAL), self.GetFileType(self.ELFfile.read(SIZE_OF_WORD))), \
('Target Machine', self.DecodeWORD(self.ELFfile_peek(SIZE_OF_WORD), HEXADECIMAL), self.GetMachineType(self.ELFfile.read(SIZE_OF_WORD))), \
('File Version', self.DecodeDWORD(self.ELFfile_peek(SIZE_OF_DWORD), HEXADECIMAL), self.GetFileVersion(self.ELFfile.read(SIZE_OF_DWORD))), \
('Entry Point Address', self.DecodeXWORD(self.ELFfile.read(SIZE_OF_XWORD), HEXADECIMAL), 'File Offset'), \
('Program Header Table', self.DecodeXWORD(self.ELFfile.read(SIZE_OF_XWORD), HEXADECIMAL), 'File Offset'), \
('Section Header Table', self.DecodeXWORD(self.ELFfile.read(SIZE_OF_XWORD), HEXADECIMAL), 'File Offset'), \
('Processor-specific Flags', self.DecodeDWORD(self.ELFfile.read(SIZE_OF_DWORD), HEXADECIMAL), ''), \
('ELF Header Size', self.DecodeWORD(self.ELFfile_peek(SIZE_OF_WORD)), self.FormatSize(self.ELFfile.read(SIZE_OF_WORD))), \
('Size of Program Header', self.DecodeWORD(self.ELFfile_peek(SIZE_OF_WORD)), self.FormatSize(self.ELFfile.read(SIZE_OF_WORD))), \
('No. of Program Headers', self.DecodeWORD(self.ELFfile.read(SIZE_OF_WORD)), ''), \
('Size of Section Header', self.DecodeWORD(self.ELFfile_peek(SIZE_OF_WORD)), self.FormatSize(self.ELFfile.read(SIZE_OF_WORD))), \
('No. of Section Headers', self.DecodeWORD(self.ELFfile.read(SIZE_OF_WORD)), ''), \
('Section name string table index', self.DecodeWORD(self.ELFfile.read(SIZE_OF_WORD)), '')]

		for data in FIELD_DATA:
			self.lstvwELFHeader.get_model().append(data)


	################# ProgramHeaderTab_OnActivate() #################
	def ProgramHeaderTab_OnActivate(self):
		# Position file pointer
		self.ELFfile.seek(self.ELFProgramHeaderFileOffset, 0)
		FIELD_DATA = []

		for i in range(self.ELFProgramHeaderNum):
			TEMP = []
			# Create listview for every Program Header
			self.tabsProgramHeader.append_page(self.lstvwProgramHeader[i], Gtk.Label('Segment ' + str(i)))

			# Connect signal for popup
			self.lstvwProgramHeader[i].connect('button-release-event', self.ListView_OnButtonRelease)

			# Read in data
			TEMP += [('Type', self.DecodeDWORD(self.ELFfile_peek(SIZE_OF_DWORD)), self.DecodeSegmentType(self.ELFfile.read(SIZE_OF_DWORD))), ]

			if self.ELFarch == ARCH_64BIT:
				TEMP += [('Attributes', self.DecodeDWORD(self.ELFfile_peek(SIZE_OF_DWORD), HEXADECIMAL), self.DecodeSegmentAttributes(self.ELFfile.read(SIZE_OF_DWORD))), ]

			TEMP += [('Offset in file', self.DecodeXWORD(self.ELFfile.read(SIZE_OF_XWORD), HEXADECIMAL), ''), \
('Virtual Address', self.DecodeXWORD(self.ELFfile.read(SIZE_OF_XWORD), HEXADECIMAL), ''), \
('Physical Address', self.DecodeXWORD(self.ELFfile.read(SIZE_OF_XWORD), HEXADECIMAL), ''), \
('Size in file', self.DecodeXWORD(self.ELFfile_peek(SIZE_OF_XWORD)), self.FormatSize(self.ELFfile.read(SIZE_OF_XWORD))), \
('Size in memory', self.DecodeXWORD(self.ELFfile_peek(SIZE_OF_XWORD)), self.FormatSize(self.ELFfile.read(SIZE_OF_XWORD))), ]

			if self.ELFarch == ARCH_32BIT:
				TEMP += [('Flags', self.DecodeDWORD(self.ELFfile_peek(SIZE_OF_DWORD)), self.DecodeSegmentAttributes(self.ELFfile.read(SIZE_OF_DWORD))), ]

			TEMP += [('Alignment', self.DecodeXWORD(self.ELFfile_peek(SIZE_OF_XWORD), HEXADECIMAL), self.FormatSize(self.ELFfile.read(SIZE_OF_XWORD))), ]

			FIELD_DATA += [(TEMP), ]

			for data in FIELD_DATA[i]:
				self.lstvwProgramHeader[i].get_model().append(data)


	################# SectionHeaderTab_OnActivate() #################
	def SectionHeaderTab_OnActivate(self):
		# Position file pointer
		self.ELFfile.seek(self.ELFSectionHeaderFileOffset, 0)
		FIELD_DATA = []

		for i in range(self.ELFSectionHeaderNum):
			# Create listview for every Section Header
			self.tabsSectionHeader.append_page(self.lstvwSectionHeader[i], Gtk.Label('Section ' + str(i)))

			# Connect signal for popup
			self.lstvwSectionHeader[i].connect('button-release-event', self.ListView_OnButtonRelease)

			# Read in data
			FIELD_DATA += [(('Name', self.DecodeDWORD(self.ELFfile_peek(SIZE_OF_DWORD)), self.DecodeSectionName(self.ELFfile.read(SIZE_OF_DWORD))), \
('Type', self.DecodeDWORD(self.ELFfile_peek(SIZE_OF_DWORD)), self.DecodeSectionType(self.ELFfile.read(SIZE_OF_DWORD))), \
('Attributes', self.DecodeXWORD(self.ELFfile_peek(SIZE_OF_XWORD), HEXADECIMAL), self.DecodeSectionAttributes(self.ELFfile.read(SIZE_OF_XWORD))), \
('Virtual Address', self.DecodeXWORD(self.ELFfile.read(SIZE_OF_XWORD), HEXADECIMAL), ''), \
('Offset in file', self.DecodeXWORD(self.ELFfile.read(SIZE_OF_XWORD), HEXADECIMAL), ''), \
('Size', self.DecodeXWORD(self.ELFfile_peek(SIZE_OF_XWORD)), self.FormatSize(self.ELFfile.read(SIZE_OF_XWORD))), \
('Link index', self.DecodeDWORD(self.ELFfile.read(SIZE_OF_DWORD)), ''), \
('Misc info', self.DecodeDWORD(self.ELFfile.read(SIZE_OF_DWORD)), ''), \
('Address alignment', self.DecodeXWORD(self.ELFfile_peek(SIZE_OF_XWORD), HEXADECIMAL), self.FormatSize(self.ELFfile.read(SIZE_OF_XWORD))), \
('Size of section table entries', self.DecodeXWORD(self.ELFfile_peek(SIZE_OF_XWORD)), self.FormatSize(self.ELFfile.read(SIZE_OF_XWORD)))), ]

			for data in FIELD_DATA[i]:
				self.lstvwSectionHeader[i].get_model().append(data)


	################## Popupmenu_Activate() ##################
	def Popupmenu_Activate(self, menuitem, listview, menuindex):
		if listview.get_selection() == None:
			return

		model = listview.get_selection().get_selected()[0]
		selection = listview.get_selection().get_selected()[1]
		clipboard = Gtk.Clipboard().get_for_display(Gdk.Display().get_default(), Gdk.SELECTION_CLIPBOARD)

		if menuindex == 0:
			# Copy Data
			clipboard.set_text(model.get_value(selection, 1), -1)

		elif menuindex == 1:
			# Copy Annotation
			clipboard.set_text(model.get_value(selection, 2), -1)
			
		elif menuindex == 2:
			# Copy Field Name
			clipboard.set_text(model.get_value(selection, 0), -1)


	############### ListView_OnButtonRelease() #################
	def ListView_OnButtonRelease(self, widget, event):
		if event.button == GTK_MOUSE_RBUTTON:
			item = widget.get_path_at_pos(event.x, event.y)

			if item != None:
				MENU_ITEMS = [Gtk.MenuItem.new_with_mnemonic('Copy _Data'), Gtk.MenuItem.new_with_mnemonic('Copy _Annotation'), Gtk.MenuItem.new_with_mnemonic('Copy _Field Name')]

				# Also make it the selected row
				itempath = item[0]
				widget.get_selection().select_path(itempath)

				# Show a popup menu
				popupmenu = Gtk.Menu()

				for i in range(len(MENU_ITEMS)):
					popupmenu.append(MENU_ITEMS[i])
					MENU_ITEMS[i].connect('activate', self.Popupmenu_Activate, widget, i)
					MENU_ITEMS[i].show()

				popupmenu.popup(None, None, lambda popupmenu, data: (event.get_root_coords()[0], event.get_root_coords()[1], True), None, event.button, event.time)


	################# get_property_pages() #################
	def get_property_pages(self, files):
		# We cannot display property page for more than one item
		if len(files) != 1:
			return

		file = files[0]	# Select the first file
		# Only 'file://' is supported
		if file.get_uri_scheme() != 'file':
			return
		
		# No use with directories
		if file.is_directory():
			return
		
		# Supports only ELF binaries
		if not file.get_mime_type() in SUPPORTED_FORMATS:
			return

		# Remove quotes after 'file://' and the end of the string
		filename = urllib.unquote(file.get_uri()[7:])

		# Open file for reading
		try:
			self.ELFfile = open(filename, 'r')

		except:
			return

		# Read ELF architecture and endianess
		self.ELFarch = self.MakeBYTE(self.ELFfile_peekAt(pos=4, size=1))
		self.ELFendian = self.MakeBYTE(self.ELFfile_peekAt(pos=5, size=1))
		global SIZE_OF_XWORD	# We are modifying the global variable below
		SIZE_OF_XWORD = SIZE_OF_DWORD if self.ELFarch == ARCH_32BIT else SIZE_OF_QWORD
		self.ELFProgramHeaderFileOffset = self.MakeXWORD(self.ELFfile_peekAt(pos=28 if self.ELFarch == ARCH_32BIT else 32, size=SIZE_OF_XWORD))
		self.ELFSectionHeaderFileOffset = self.MakeXWORD(self.ELFfile_peekAt(pos=32 if self.ELFarch == ARCH_32BIT else 40, size=SIZE_OF_XWORD))
		self.ELFSectionNameTableFileOffset = 0 if (self.ELFSectionHeaderFileOffset == 0 or self.MakeWORD(self.ELFfile_peekAt(pos=(50 if self.ELFarch == ARCH_32BIT else 62), size=SIZE_OF_WORD)) == 0) else self.MakeXWORD(self.ELFfile_peekAt(pos=(self.ELFSectionHeaderFileOffset + (self.MakeWORD(self.ELFfile_peekAt(pos=(50 if self.ELFarch == ARCH_32BIT else 62), size=SIZE_OF_WORD)) * (40 if self.ELFarch == ARCH_32BIT else 64) + (16 if self.ELFarch == ARCH_32BIT else 24))), size=SIZE_OF_XWORD))
		self.ELFHasProgramHeader = True if self.ELFProgramHeaderFileOffset != 0 else False
		self.ELFHasSectionHeader = True if self.ELFSectionHeaderFileOffset != 0 else False
		self.ELFHasSectionNameTable = (self.ELFSectionNameTableFileOffset != 0)
		self.ELFProgramHeaderNum = self.MakeWORD(self.ELFfile_peekAt(pos=44 if self.ELFarch == ARCH_32BIT else 56, size=SIZE_OF_WORD))
		self.ELFSectionHeaderNum = self.MakeWORD(self.ELFfile_peekAt(pos=48 if self.ELFarch == ARCH_32BIT else 60, size=SIZE_OF_WORD))

		# Tab labels for property pages
		ELFHeadertab_label = Gtk.Label('ELF Header')
		ELFHeadertab_label.show()

		if self.ELFHasProgramHeader:
			ProgramHeadertab_label = Gtk.Label('Program Header')
			ProgramHeadertab_label.show()

		if self.ELFHasSectionHeader:
			SectionHeadertab_label = Gtk.Label('Section Header')
			SectionHeadertab_label.show()

		# Create controls
		self.srllwinELFHeader = Gtk.ScrolledWindow()
		self.lstvwELFHeader = Gtk.TreeView(Gtk.ListStore(str, str, str))
		self.srllwinELFHeader.add_with_viewport(self.lstvwELFHeader)
		self.srllwinELFHeader.show()
		self.lstvwELFHeader.show()

		if self.ELFHasProgramHeader:
			self.srllwinProgramHeader = Gtk.ScrolledWindow()
			self.tabsProgramHeader = Gtk.Notebook()
			self.tabsProgramHeader.set_scrollable(True)
			self.srllwinProgramHeader.add_with_viewport(self.tabsProgramHeader)
			self.srllwinProgramHeader.show()
			self.tabsProgramHeader.show()

			self.lstvwProgramHeader = []
			for i in range(self.ELFProgramHeaderNum):
				self.lstvwProgramHeader += (Gtk.TreeView(Gtk.ListStore(str, str, str)), )
				self.lstvwProgramHeader[i].show()

		if self.ELFHasSectionHeader:
			self.srllwinSectionHeader = Gtk.ScrolledWindow()
			self.tabsSectionHeader = Gtk.Notebook()
			self.tabsSectionHeader.set_scrollable(True)
			self.srllwinSectionHeader.add_with_viewport(self.tabsSectionHeader)
			self.srllwinSectionHeader.show()
			self.tabsSectionHeader.show()

			self.lstvwSectionHeader = []
			for i in range(self.ELFSectionHeaderNum):
				self.lstvwSectionHeader += (Gtk.TreeView(Gtk.ListStore(str, str, str)), )
				self.lstvwSectionHeader[i].show()

		for i in range(len(GENERIC_COLUMN_NAMES)):
			self.lstvwELFHeader.append_column(Gtk.TreeViewColumn(GENERIC_COLUMN_NAMES[i], Gtk.CellRendererText(), text=i))

			if self.ELFHasProgramHeader:
				for j in range(self.ELFProgramHeaderNum):
					self.lstvwProgramHeader[j].append_column(Gtk.TreeViewColumn(GENERIC_COLUMN_NAMES[i], Gtk.CellRendererText(), text=i))

			if self.ELFHasSectionHeader:
				for k in range(self.ELFSectionHeaderNum):
					self.lstvwSectionHeader[k].append_column(Gtk.TreeViewColumn(GENERIC_COLUMN_NAMES[i], Gtk.CellRendererText(), text=i))

		# Horizontal Box for layout
		ELFHeadertab_hbox = Gtk.HBox(homogeneous=False, spacing=10)
		ELFHeadertab_hbox.show()

		if self.ELFHasProgramHeader:
			ProgramHeadertab_hbox = Gtk.HBox(homogeneous=False, spacing=10)
			ProgramHeadertab_hbox.show()

		if self.ELFHasSectionHeader:
			SectionHeadertab_hbox = Gtk.HBox(homogeneous=False, spacing=10)
			SectionHeadertab_hbox.show()

		# Assign controls to Horizontal Box
		ELFHeadertab_hbox.pack_start(self.srllwinELFHeader, True, True, 10)

		if self.ELFHasProgramHeader:
			ProgramHeadertab_hbox.pack_start(self.srllwinProgramHeader, True, True, 10)
		if self.ELFHasSectionHeader:
			SectionHeadertab_hbox.pack_start(self.srllwinSectionHeader, True, True, 10)

		# Create property pages
		propertypages = (Nautilus.PropertyPage(name='NautilusPython::ELFHeaderPropertyPage', label=ELFHeadertab_label, page=ELFHeadertab_hbox), )

		if self.ELFHasProgramHeader:
			propertypages += (Nautilus.PropertyPage(name='NautilusPython::ProgramHeaderPropertyPage', label=ProgramHeadertab_label, page=ProgramHeadertab_hbox), )

		if self.ELFHasSectionHeader:
			propertypages += (Nautilus.PropertyPage(name='NautilusPython::SectionHeaderPropertyPage', label=SectionHeadertab_label, page=SectionHeadertab_hbox), )

		# Connect signals to associated functions
		#propertypages[0].connect('callback', self.ELFHeaderTab_OnActivate)

		self.ELFHeaderTab_OnActivate()

		if self.ELFHasProgramHeader:
			self.ProgramHeaderTab_OnActivate()
		if self.ELFHasSectionHeader:
			self.SectionHeaderTab_OnActivate()

		return propertypages
