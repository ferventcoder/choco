// Copyright © 2011 - Present RealDimensions Software, LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// 
// You may obtain a copy of the License at
// 
// 	http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace chocolatey.infrastructure.app.domain
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;

    // ReSharper disable InconsistentNaming

    /// <summary>
    /// </summary>
    /// <remarks>Based on http://sergeyakopov.com/reading-pe-format-using-data-marshaling-in-net/ </remarks>
    public class PEHeader
    {
        // http://pinvoke.net/default.aspx/Structures.IMAGE_DOS_HEADER 
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic; // Magic number
            public UInt16 e_cblp; // Bytes on last page of file
            public UInt16 e_cp; // Pages in file
            public UInt16 e_crlc; // Relocations
            public UInt16 e_cparhdr; // Size of header in paragraphs
            public UInt16 e_minalloc; // Minimum extra paragraphs needed
            public UInt16 e_maxalloc; // Maximum extra paragraphs needed
            public UInt16 e_ss; // Initial (relative) SS value
            public UInt16 e_sp; // Initial SP value
            public UInt16 e_csum; // Checksum
            public UInt16 e_ip; // Initial IP value
            public UInt16 e_cs; // Initial (relative) CS value
            public UInt16 e_lfarlc; // File address of relocation table
            public UInt16 e_ovno; // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1; // Reserved words
            public UInt16 e_oemid; // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo; // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2; // Reserved words
            public Int32 e_lfanew; // File address of new exe header
        }

        // http://pinvoke.net/default.aspx/Structures.IMAGE_NT_HEADERS
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
        }

        // http://pinvoke.net/default.aspx/Structures/IMAGE_FILE_HEADER.html
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        // http://pinvoke.net/default.aspx/Structures.IMAGE_OPTIONAL_HEADER32
        // this section differs significantly from the url and is a closer match to the post
        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        // http://pinvoke.net/default.aspx/Structures/IMAGE_DATA_DIRECTORY.html
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        // http://pinvoke.net/default.aspx/Structures/IMAGE_SECTION_HEADER.html
        // this is different from the url above, more closely follows the post
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;
            public IMAGE_SECTION_HEADER_MISC Misc;
            public UInt32 VirtualAddress;
            public UInt32 SizeOfRawData;
            public UInt32 PointerToRawData;
            public UInt32 PointerToRelocations;
            public UInt32 PointerToLinenumbers;
            public UInt16 NumberOfRelocations;
            public UInt16 NumberOfLinenumbers;
            public UInt32 Characteristics;
        }

        // used for Characteristics above
        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,
            /// <summary>
            ///   The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,
            /// <summary>
            ///   The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,
            /// <summary>
            ///   The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,
            /// <summary>
            ///   The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,
            /// <summary>
            ///   The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,
            /// <summary>
            ///   The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,
            /// <summary>
            ///   The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,
            /// <summary>
            ///   Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,
            /// <summary>
            ///   The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,
            /// <summary>
            ///   Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,
            /// <summary>
            ///   Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,
            /// <summary>
            ///   Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,
            /// <summary>
            ///   Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,
            /// <summary>
            ///   Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,
            /// <summary>
            ///   Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,
            /// <summary>
            ///   Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,
            /// <summary>
            ///   Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,
            /// <summary>
            ///   Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,
            /// <summary>
            ///   Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,
            /// <summary>
            ///   Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,
            /// <summary>
            ///   Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,
            /// <summary>
            ///   Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,
            /// <summary>
            ///   Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,
            /// <summary>
            ///   Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,
            /// <summary>
            ///   The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,
            /// <summary>
            ///   The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,
            /// <summary>
            ///   The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,
            /// <summary>
            ///   The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,
            /// <summary>
            ///   The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,
            /// <summary>
            ///   The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,
            /// <summary>
            ///   The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,
            /// <summary>
            ///   The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER_MISC
        {
            [FieldOffset(0)]
            public UInt32 PhysicalAddress;
            [FieldOffset(0)]
            public UInt32 VirtualSize;
        }

        private readonly IMAGE_DOS_HEADER _dosHeader;
        private IMAGE_NT_HEADERS _ntHeaders;
        private readonly IList<IMAGE_SECTION_HEADER> _sectionHeaders = new List<IMAGE_SECTION_HEADER>();

        public PEHeader(string filePath)
        {
            var reader = new BinaryReader(new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read));
            // Reset reader position, just in case
            reader.BaseStream.Seek(0, SeekOrigin.Begin);

            // Read MS-DOS header section
            _dosHeader = MarshalBytesTo<IMAGE_DOS_HEADER>(reader);

            // MS-DOS magic number should read 'MZ'
            if (new string(_dosHeader.e_magic).to_lower() != "mz")
            {
                throw new InvalidOperationException("File is not a portable executable.");
            }

            // Skip MS-DOS stub and seek reader to NT Headers
            reader.BaseStream.Seek(_dosHeader.e_lfanew, SeekOrigin.Begin);

            // Read NT Headers
            _ntHeaders.Signature = MarshalBytesTo<UInt32>(reader);

            // Make sure we have 'PE' in the pe signature
            if (_ntHeaders.Signature != 0x4550)
            {
                throw new InvalidOperationException("Invalid portable executable signature in NT header.");
            }

            _ntHeaders.FileHeader = MarshalBytesTo<IMAGE_FILE_HEADER>(reader);

            // Read optional headers
            if (Is32bitAssembly(_ntHeaders))
            {
                Load32bitOptionalHeaders(reader);
            }
            else
            {
                Load64bitOptionalHeaders(reader);
            }

            // Read section data
            foreach (IMAGE_SECTION_HEADER header in _sectionHeaders)
            {
                // Skip to beginning of a section
                reader.BaseStream.Seek(header.PointerToRawData, SeekOrigin.Begin);

                // Read section data... and do something with it
                byte[] sectiondata = reader.ReadBytes((int)header.SizeOfRawData);
            }
        }

        public IMAGE_DOS_HEADER GetDOSHeader()
        {
            return _dosHeader;
        }

        public UInt32 GetPESignature()
        {
            return _ntHeaders.Signature;
        }

        public IMAGE_FILE_HEADER GetFileHeader()
        {
            return _ntHeaders.FileHeader;
        }

        public IMAGE_OPTIONAL_HEADER32 GetOptionalHeaders32()
        {
            return _ntHeaders.OptionalHeader32;
        }

        public IMAGE_OPTIONAL_HEADER64 GetOptionalHeaders64()
        {
            return _ntHeaders.OptionalHeader64;
        }

        public IList<IMAGE_SECTION_HEADER> GetSectionHeaders()
        {
            return _sectionHeaders;
        }

        public bool Is32bitAssembly(IMAGE_NT_HEADERS headers)
        {
            return ((headers.FileHeader.Characteristics & 0x0100) == 0x0100);
        }

        private void Load64bitOptionalHeaders(BinaryReader reader)
        {
            _ntHeaders.OptionalHeader64 = MarshalBytesTo<IMAGE_OPTIONAL_HEADER64>(reader);

            // Should have 10 data directories
            if (_ntHeaders.OptionalHeader64.NumberOfRvaAndSizes != 0x10)
            {
                throw new InvalidOperationException("Invalid number of data directories in NT header");
            }

            // Scan data directories and load section headers
            for (int i = 0; i < _ntHeaders.OptionalHeader64.NumberOfRvaAndSizes; i++)
            {
                if (_ntHeaders.OptionalHeader64.DataDirectory[i].Size > 0)
                {
                    _sectionHeaders.Add(MarshalBytesTo<IMAGE_SECTION_HEADER>(reader));
                }
            }
        }

        private void Load32bitOptionalHeaders(BinaryReader reader)
        {
            _ntHeaders.OptionalHeader32 = MarshalBytesTo<IMAGE_OPTIONAL_HEADER32>(reader);

            // Should have 10 data directories
            if (_ntHeaders.OptionalHeader32.NumberOfRvaAndSizes != 0x10)
            {
                throw new InvalidOperationException("Invalid number of data directories in NT header");
            }

            // Scan data directories and load section headers
            for (int i = 0; i < _ntHeaders.OptionalHeader32.NumberOfRvaAndSizes; i++)
            {
                if (_ntHeaders.OptionalHeader32.DataDirectory[i].Size > 0)
                {
                    _sectionHeaders.Add(MarshalBytesTo<IMAGE_SECTION_HEADER>(reader));
                }
            }
        }

        private static T MarshalBytesTo<T>(BinaryReader reader)
        {
            // Unmanaged data
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Create a pointer to the unmanaged data pinned in memory to be accessed by unmanaged code
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);

            // Use our previously created pointer to unmanaged data and marshal to the specified type
            var theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));

            // Deallocate pointer
            handle.Free();

            return theStructure;
        }
    }

    public class testheaders
    {
        public void testheader()
        {
            var header = new PEHeader(@"C:\die-test\7z1514-x64.exe");
            var binaryData = get_file_data(@"C:\die-test\7z1514-x64.exe");
            Console.WriteLine("7z contains 7zip? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("7z")));
            Console.WriteLine("7z contains Inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Inno")));
            Console.WriteLine("7z contains Wise? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Wise")));
            Console.WriteLine("7z contains Nullsoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Nullsoft")));
            Console.WriteLine("7z contains NullSoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("NullSoft")));
            header = new PEHeader(@"C:\die-test\Git-2.7.0-32-bit.exe");
            binaryData = get_file_data(@"C:\die-test\Git-2.7.0-32-bit.exe");
            Console.WriteLine("Git contains Inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Inno")));
            Console.WriteLine("Git contains Wise? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Wise")));
            Console.WriteLine("Git contains Nullsoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Nullsoft")));
            Console.WriteLine("Git contains NullSoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("NullSoft")));
            header = new PEHeader(@"C:\die-test\Git-2.7.0-64-bit.exe");
            binaryData = get_file_data(@"C:\die-test\Git-2.7.0-64-bit.exe");
            Console.WriteLine("Git contains Inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Inno")));
            Console.WriteLine("Git contains inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("inno")));
            Console.WriteLine("Git contains Wise? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Wise")));
            Console.WriteLine("Git contains Nullsoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Nullsoft")));
            Console.WriteLine("Git contains NullSoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("NullSoft")));
            //header = new PEHeader(@"C:\die-test\GoogleChromeStandaloneEnterprise.msi");
            binaryData = get_file_data(@"C:\die-test\GoogleChromeStandaloneEnterprise.msi");
            Console.WriteLine("Chrome contains Inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Inno")));
            Console.WriteLine("Chrome contains inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("inno")));
            Console.WriteLine("Chrome contains Wise? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Wise")));
            Console.WriteLine("Chrome contains Nullsoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Nullsoft")));
            Console.WriteLine("Chrome contains NullSoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("NullSoft")));
            //header = new PEHeader(@"C:\die-test\node-v5.4.0-x86.msi");
            binaryData = get_file_data(@"C:\die-test\node-v5.4.0-x86.msi");
            Console.WriteLine("Node contains Inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Inno")));
            Console.WriteLine("Node contains inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("inno")));
            Console.WriteLine("Node contains Wise? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Wise")));
            Console.WriteLine("Node contains Nullsoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Nullsoft")));
            Console.WriteLine("Node contains NullSoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("NullSoft")));

            header = new PEHeader(@"C:\die-test\npp.6.8.8.Installer.exe");
            binaryData = get_file_data(@"C:\die-test\npp.6.8.8.Installer.exe");
            Console.WriteLine("N++ contains Inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Inno")));
            Console.WriteLine("N++ contains inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("inno")));
            Console.WriteLine("N++ contains Wise? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Wise")));
            Console.WriteLine("N++ contains Nullsoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Nullsoft")));
            Console.WriteLine("N++ contains NullSoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("NullSoft")));

            //header = new PEHeader(@"C:\die-test\puppet-agent-1.3.2-x64.msi");
            binaryData = get_file_data(@"C:\die-test\puppet-agent-1.3.2-x64.msi");
            Console.WriteLine("puppet-agent contains Inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Inno")));
            Console.WriteLine("puppet-agent contains inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("inno")));
            Console.WriteLine("puppet-agent contains Wise? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Wise")));
            Console.WriteLine("puppet-agent contains Nullsoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Nullsoft")));
            Console.WriteLine("puppet-agent contains NullSoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("NullSoft")));

           // header = new PEHeader(@"C:\die-test\vagrant_1.8.1.msi");
            binaryData = get_file_data(@"C:\die-test\vagrant_1.8.1.msi");
            Console.WriteLine("Vagrant contains Inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Inno")));
            Console.WriteLine("Vagrant contains inno? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("inno")));
            Console.WriteLine("Vagrant contains Wise? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Wise")));
            Console.WriteLine("Vagrant contains Nullsoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("Nullsoft")));
            Console.WriteLine("Vagrant contains NullSoft? ={0}", binaryData.contains(Encoding.ASCII.GetBytes("NullSoft")));


            var i = 1;
        }

        private byte[] get_file_data(string filePath)
        {
            var fileData = string.Empty;

            return File.ReadAllBytes(filePath);

            //using (FileStream fs = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read))
            //using (BinaryReader reader = new BinaryReader(fs))
            //{
            //    byte[] bin = reader.ReadBytes(8192);

            //    var mz = Encoding.ASCII.GetBytes("MZ");

            //    fileData = System.Text.Encoding.ASCII.GetString(bin);
            //    fs.Flush();
            //    fs.Close();
            //    reader.Close();
            //    fs.Dispose();
            //    reader.Dispose();
            //}

            //FileStream fileStream = File.Open(filePath, FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);
            //byte[] data = new byte[8192];
            //// Put in the first 4k of the file into our byte array
            //fileStream.Read(data, 0, data.Length); 

            //fileStream.Flush();
            //fileStream.Close();
            //fileStream.Dispose();

            //return fileData;
        }
    }
    // ReSharper restore InconsistentNaming
}