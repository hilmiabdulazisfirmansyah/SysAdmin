import struct
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

class DiskScanner:
    def __init__(self, disk_path, sector_size=512):
        """
        Inisialisasi scanner untuk disk atau image file
        """
        self.disk_path = disk_path
        self.sector_size = sector_size
        self.partitions = []
        self.recovered_files = []

    def open_disk(self):
        """Buka disk/file image untuk membaca"""
        try:
            if sys.platform == 'win32':
                # Windows - butuh akses administrator
                import win32file
                return open(r'\\.\PhysicalDrive0', 'rb') if self.disk_path == 'physical' else open(self.disk_path, 'rb')
            else:
                # Linux/Mac
                return open(self.disk_path, 'rb')
        except Exception as e:
            print(f"Error opening disk: {e}")
            print("Note: On Linux/Mac, run with sudo")
            print("On Windows, run as Administrator")
            return None

    def read_sector(self, fd, sector_num):
        """Baca satu sektor dari disk"""
        try:
            fd.seek(sector_num * self.sector_size)
            return fd.read(self.sector_size)
        except:
            return None

    def analyze_mbr(self, fd):
        """Analisis MBR (Master Boot Record) di sektor 0"""
        print("\n" + "="*60)
        print("ANALYZING MASTER BOOT RECORD (MBR)")
        print("="*60)

        mbr = self.read_sector(fd, 0)
        if not mbr:
            print("Cannot read MBR")
            return False

        # Cek signature MBR (0x55AA di akhir)
        if mbr[510] != 0x55 or mbr[511] != 0xAA:
            print("MBR signature invalid (should be 0x55AA)")
            return False

        print(f"MBR Signature: OK (0x55AA)")

        # Parse 4 partisi entries di MBR
        partitions = []
        for i in range(4):
            offset = 446 + (i * 16)
            entry = mbr[offset:offset+16]

            if entry[4] == 0x00:  # Empty partition
                continue

            # Parse partisi entry
            status = entry[0]
            type_code = entry[4]
            lba_start = struct.unpack('<I', entry[8:12])[0]
            num_sectors = struct.unpack('<I', entry[12:16])[0]

            partition_info = {
                'number': i + 1,
                'status': status,
                'type': type_code,
                'lba_start': lba_start,
                'num_sectors': num_sectors,
                'size_mb': (num_sectors * self.sector_size) / (1024 * 1024),
                'type_desc': self.get_partition_type(type_code)
            }

            partitions.append(partition_info)

            print(f"\nPartition {i+1}:")
            print(f"  Type: 0x{type_code:02X} ({partition_info['type_desc']})")
            print(f"  Start LBA: {lba_start}")
            print(f"  Sectors: {num_sectors}")
            print(f"  Size: {partition_info['size_mb']:.2f} MB")
            print(f"  Status: {'Active' if status == 0x80 else 'Inactive'}")

        self.partitions = partitions
        return len(partitions) > 0

    def get_partition_type(self, type_code):
        """Dapatkan deskripsi tipe partisi"""
        types = {
            0x07: "NTFS",
            0x0B: "FAT32",
            0x0C: "FAT32 (LBA)",
            0x0E: "FAT16 (LBA)",
            0x83: "Linux",
            0x05: "Extended",
            0x0F: "Extended (LBA)",
            0xEE: "GPT Protective",
        }
        return types.get(type_code, f"Unknown (0x{type_code:02X})")

    def search_lost_partitions(self, fd, start_sector=0, end_sector=100000):
        """Cari partisi yang hilang dengan scan sector-by-sector"""
        print("\n" + "="*60)
        print("SEARCHING FOR LOST PARTITIONS")
        print("="*60)

        lost_partitions = []
        total_sectors = min(end_sector, 1000000)  # Batasi untuk demo

        print(f"Scanning sectors {start_sector} to {total_sectors}...")
        print("This may take a while...")

        for sector in range(start_sector, total_sectors):
            data = self.read_sector(fd, sector)
            if not data:
                break

            # Cari signature partisi di awal sector
            # NTFS: "NTFS" di offset 3
            # FAT: "FAT" di offset 54 atau 36
            if len(data) >= 512:
                # Cek NTFS
                if data[3:8] == b'NTFS    ':
                    print(f"[+] Found NTFS at sector {sector}")
                    lost_partitions.append({
                        'type': 'NTFS',
                        'sector': sector,
                        'boot_sector': sector
                    })

                # Cek FAT
                elif data[54:57] in [b'FAT', b'FAT12', b'FAT16']:
                    print(f"[+] Found FAT at sector {sector}")
                    lost_partitions.append({
                        'type': 'FAT',
                        'sector': sector,
                        'boot_sector': sector
                    })

            # Progress indicator
            if sector % 10000 == 0 and sector > 0:
                progress = (sector / total_sectors) * 100
                print(f"Progress: {progress:.1f}% ({sector}/{total_sectors} sectors)")

        return lost_partitions

    def analyze_ntfs(self, fd, start_sector):
        """Analisis struktur NTFS"""
        print(f"\nAnalyzing NTFS at sector {start_sector}...")

        # Baca boot sector NTFS
        boot = self.read_sector(fd, start_sector)
        if not boot or boot[3:8] != b'NTFS    ':
            print("Not a valid NTFS boot sector")
            return None

        # Parse BPB (BIOS Parameter Block)
        bytes_per_sector = struct.unpack('<H', boot[11:13])[0]
        sectors_per_cluster = boot[13]
        mft_cluster = struct.unpack('<Q', boot[48:56])[0]

        print(f"Bytes per sector: {bytes_per_sector}")
        print(f"Sectors per cluster: {sectors_per_cluster}")
        print(f"MFT start cluster: {mft_cluster}")

        return {
            'bytes_per_sector': bytes_per_sector,
            'sectors_per_cluster': sectors_per_cluster,
            'mft_cluster': mft_cluster
        }

    def recover_files_from_fat(self, fd, start_sector, output_dir):
        """Recover file dari FAT (sederhana)"""
        print(f"\nAttempting FAT file recovery from sector {start_sector}...")

        # Ini adalah implementasi sederhana
        # Untuk implementasi lengkap, perlu parsing FAT table

        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        recovered_count = 0

        # Scan untuk file signatures umum
        signatures = {
            b'\xFF\xD8\xFF': ('jpg', 'JPEG Image'),
            b'\x89PNG': ('png', 'PNG Image'),
            b'%PDF': ('pdf', 'PDF Document'),
            b'PK\x03\x04': ('zip', 'ZIP Archive'),
            b'\xD0\xCF\x11\xE0': ('doc', 'MS Office Document'),
        }

        print("Scanning for file signatures...")

        # Scan beberapa sector setelah boot sector
        for sector_offset in range(0, 1000):
            sector = start_sector + sector_offset
            data = self.read_sector(fd, sector)

            if not data:
                break

            # Cek setiap signature
            for sig, (ext, desc) in signatures.items():
                pos = data.find(sig)
                if pos != -1:
                    # Temukan file - untuk demo, simpan sector saja
                    filename = f"recovered_{recovered_count:04d}.{ext}"
                    filepath = output_path / filename

                    # Simpan beberapa sector sebagai file
                    with open(filepath, 'wb') as f:
                        # Ambil 100KB data (200 sectors)
                        for i in range(200):
                            sector_data = self.read_sector(fd, sector + i)
                            if sector_data:
                                f.write(sector_data)

                    recovered_count += 1
                    print(f"  Recovered: {filename}")

        print(f"\nTotal files recovered: {recovered_count}")
        return recovered_count

    def create_disk_image(self, fd, start_sector, num_sectors, output_file):
        """Buat image dari range sector tertentu"""
        print(f"\nCreating disk image: {output_file}")
        print(f"From sector {start_sector} for {num_sectors} sectors")

        try:
            with open(output_file, 'wb') as img:
                for i in range(num_sectors):
                    sector = start_sector + i
                    data = self.read_sector(fd, sector)
                    if not data:
                        break
                    img.write(data)

                    if i % 100 == 0:
                        progress = (i / num_sectors) * 100
                        print(f"Progress: {progress:.1f}%", end='\r')

            print(f"\nImage created: {output_file}")
            size_mb = (num_sectors * self.sector_size) / (1024 * 1024)
            print(f"Size: {size_mb:.2f} MB")
            return True
        except Exception as e:
            print(f"Error creating image: {e}")
            return False

    def print_summary(self):
        """Print summary hasil scan"""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Disk/Image: {self.disk_path}")
        print(f"Sector Size: {self.sector_size} bytes")
        print(f"Partitions Found: {len(self.partitions)}")

        for i, p in enumerate(self.partitions):
            print(f"\nPartition {i+1}:")
            print(f"  Type: {p['type_desc']}")
            print(f"  Start: Sector {p['lba_start']}")
            print(f"  Size: {p['size_mb']:.2f} MB")
            print(f"  Status: {'Active' if p['status'] == 0x80 else 'Inactive'}")

        print(f"\nFiles Recovered: {len(self.recovered_files)}")


def main():
    parser = argparse.ArgumentParser(
        description="PyDiskRecovery - Simple disk recovery tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python pydiskrecovery.py --disk /dev/sda --analyze
  python pydiskrecovery.py --image disk.img --search
  python pydiskrecovery.py --disk /dev/sdb --recover-files --output recovered/
        """
    )

    parser.add_argument('--disk', help='Physical disk path (e.g., /dev/sda on Linux)')
    parser.add_argument('--image', help='Disk image file path')
    parser.add_argument('--analyze', action='store_true', help='Analyze MBR/GPT')
    parser.add_argument('--search', action='store_true', help='Search for lost partitions')
    parser.add_argument('--recover-files', action='store_true', help='Attempt file recovery')
    parser.add_argument('--output', default='recovered', help='Output directory for recovered files')
    parser.add_argument('--sector-size', type=int, default=512, help='Sector size in bytes')

    args = parser.parse_args()

    # Tentukan disk path
    disk_path = args.disk or args.image
    if not disk_path:
        if sys.platform == 'win32':
            disk_path = r'\\.\PhysicalDrive0'
        else:
            disk_path = '/dev/sda'
        print(f"No disk specified, using default: {disk_path}")

    # Buat scanner
    scanner = DiskScanner(disk_path, args.sector_size)

    # Buka disk
    fd = scanner.open_disk()
    if not fd:
        sys.exit(1)

    try:
        if args.analyze:
            scanner.analyze_mbr(fd)

        if args.search:
            lost = scanner.search_lost_partitions(fd, 0, 50000)
            if lost:
                print(f"\nFound {len(lost)} potential lost partitions")
                for p in lost:
                    print(f"  {p['type']} at sector {p['sector']}")
            else:
                print("\nNo lost partitions found in scanned range")

        if args.recover_files:
            # Untuk demo, coba recover dari sector tertentu
            # Dalam aplikasi nyata, ini akan ditentukan dari hasil scan
            scanner.recover_files_from_fat(fd, 2048, args.output)

        scanner.print_summary()

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        fd.close()


if __name__ == "__main__":
    print("PyDiskRecovery v1.0 - Educational Disk Recovery Tool")
    print("="*60)
    print("WARNING: This tool is for educational purposes only!")
    print("Always backup your data before attempting recovery.")
    print("="*60)

    main()
