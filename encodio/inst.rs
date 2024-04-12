#[cfg(feature = "signature-pgp")]
use rpm::{
    IndexTag,
    signature::pgp::{
        Verifier
    },
};
use libc;
use zstd::zstd_safe;
use std::os::fd::AsRawFd;
use std::io::{
    Read,
    Seek,
    Error,
    ErrorKind,
};
use std::os::unix::fs::FileExt;
use std::path::Path;

#[cfg(debug_assertions)]
macro_rules! dout {
    ($($l:tt)*) => { println!($($l)*); }
}
#[cfg(not(debug_assertions))]
macro_rules! dout {
    ($($l:tt)*) => {};
}


fn usage(prog: &String) {
    println!("usage: {} rpm-path encoded-output install-root", prog);
}

#[repr(C)]
pub struct iovec {
    pub iov_base: *mut std::ffi::c_void,
    pub iov_len: usize,	// size_t
}
#[repr(C)]
pub struct btrfs_ioctl_encoded_io_args {
    pub iov: *mut std::ffi::c_void,
    pub iovcnt: std::os::raw::c_ulong,
    pub offset: i64,
    pub flags: u64,
    pub len: u64,
    pub unencoded_len: u64,
    pub unencoded_offset: u64,
    pub compression: u32,
    pub encryption: u32,
    pub reserved: [u8; 64],
}

//consts are pub for #[allow(unused)]
// strace: ioctl(0x4, 0x40809440, 0x7ffdb487c010)  = 0x357
pub const BTRFS_IOC_ENCODED_WRITE: std::os::raw::c_ulong = 0x40809440;

pub const BTRFS_ENCODED_IO_COMPRESSION_NONE: u32 = 0;
pub const BTRFS_ENCODED_IO_COMPRESSION_ZLIB: u32 = 1;
pub const BTRFS_ENCODED_IO_COMPRESSION_ZSTD: u32 = 2;
pub const BTRFS_ENCODED_IO_COMPRESSION_LZO_4K: u32 = 3;
pub const BTRFS_ENCODED_IO_COMPRESSION_LZO_8K: u32 = 4;
pub const BTRFS_ENCODED_IO_COMPRESSION_LZO_16K: u32 = 5;
pub const BTRFS_ENCODED_IO_COMPRESSION_LZO_32K: u32 = 6;
pub const BTRFS_ENCODED_IO_COMPRESSION_LZO_64K: u32 = 7;

pub const BTRFS_ENCODED_IO_ENCRYPTION_NONE: u32 = 0;

pub const BTRFS_MAX_COMPRESSED: usize = 128 * 1024;
pub const BTRFS_MAX_UNCOMPRESSED: u64 = 128 * 1024;
// XXX values below need to be checked with kernel
pub const BTRFS_MIN_COMPRESSED: usize = 4096;
pub const BTRFS_MIN_UNCOMPRESSED: u64 = 4096;

fn decompress_fallback(dstf: &std::fs::File, src_frame: &[u8], uncompressed_off: u64, uncompressed_sz: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut froutbuf = Vec::with_capacity(uncompressed_sz);
    eprintln!("manually decompressing {} byte chunk as zstd frame", src_frame.len());
    match zstd_safe::decompress(&mut froutbuf, src_frame) {
        Err(e) => {
            let es = zstd_safe::get_error_name(e);
            eprintln!("decompress() failed: {}", es);
            return Err(Box::new(Error::new(ErrorKind::Other, es)));
        },
        Ok(l) => {
            eprintln!("decompress returned: {}", l);
            assert!(l == uncompressed_sz);
        }
    };
    eprintln!("writing decompressed {} data to offset {}", froutbuf.len(), uncompressed_off);
    dstf.write_all_at(&froutbuf, uncompressed_off)?;
    Ok(())
}

fn encoded_copy_payload(src_data: &mut Vec<u8>, dst_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dstf = std::fs::File::create(dst_path)?;
    let dfd = dstf.as_raw_fd();
    let mut remaining = src_data.len();
    let mut data_off = 0;
    let mut uncompressed_off: u64 = 0;

    while remaining > 0 {
        // XXX btrfs encoded write's currently need to provide the unencoded
        // length. TODO: add a get_wr_lens_from_frame kernel flag.
        let compressed_sz = match zstd_safe::find_frame_compressed_size(&src_data[data_off..]) {
            Err(e) => {
                let es = zstd_safe::get_error_name(e);
                eprintln!("zstd find_frame_compressed_size() failed {}", es);
                return Err(Box::new(Error::new(ErrorKind::UnexpectedEof, es)));
            },
            Ok(l) => l,
        };
        let uncompressed_sz = match zstd_safe::get_frame_content_size(&src_data[data_off..]) {
            Err(e) => {
                eprintln!("zstd get_frame_content_size() failed {}", e);
                return Err(Box::new(Error::new(ErrorKind::UnexpectedEof,
                    "failed to get unencoded frame content length",
                )));
            },
            Ok(s) => match s {
                Some(l) => l,
                None => 0,
            },
        };

        dout!("zstd frame size {} with content size: {}",
            compressed_sz, uncompressed_sz);

        if compressed_sz > remaining {
            return Err(Box::new(Error::new(ErrorKind::UnexpectedEof,
                "zstd frame larger than remaining buffer",
            )));
        }
        let this_len = compressed_sz;
        let body_slice: &mut [u8] = &mut src_data[data_off..data_off+this_len];

        if compressed_sz > BTRFS_MAX_COMPRESSED {
            panic!("TODO: decompress and write");
        }
        if uncompressed_sz > BTRFS_MAX_UNCOMPRESSED {
            panic!("TODO: decompress and write");
        }

        //if compressed_sz < BTRFS_MIN_COMPRESSED || uncompressed_sz < BTRFS_MIN_UNCOMPRESSED {
        if uncompressed_sz < BTRFS_MIN_UNCOMPRESSED {
            decompress_fallback(&dstf, body_slice, uncompressed_off, uncompressed_sz.try_into().unwrap())?;
            remaining -= this_len;
            data_off += this_len;
            uncompressed_off += uncompressed_sz;
            continue;
        }

        //dstf.set_len(uncompressed_off + uncompressed_sz)?;

        let mut iov = iovec{
            iov_base: body_slice.as_mut_ptr() as *mut std::ffi::c_void,
            iov_len: body_slice.len(),
        };
        let iov_ptr: *mut std::ffi::c_void = &mut iov as *mut _ as *mut std::ffi::c_void;
        let mut encio = btrfs_ioctl_encoded_io_args{
            iov: iov_ptr,
            iovcnt: 1,
            offset: uncompressed_off.try_into().unwrap(),
            flags: 0,
            len: uncompressed_sz,
            unencoded_len: uncompressed_sz,
            unencoded_offset: 0,  // XXX unencoded vals don't make much sense
            compression: BTRFS_ENCODED_IO_COMPRESSION_ZSTD,
            encryption: BTRFS_ENCODED_IO_ENCRYPTION_NONE,
            reserved: [0; 64],
        };
        let encio_ptr: *mut std::ffi::c_void = &mut encio as *mut _ as *mut std::ffi::c_void;

        match unsafe { libc::ioctl(dfd, BTRFS_IOC_ENCODED_WRITE, encio_ptr) } {
            -1 => {
                eprintln!("encoded write ioctl failed");
                // TODO fallback to extract+write (if first ioctl call?)
                return Err(Box::new(Error::last_os_error()))
            },
            v if v != this_len.try_into().unwrap() => {
                eprintln!("encoded write ioctl len mismatch. expected {} got {}",
                    this_len, v);
                return Err(Box::new(Error::new(ErrorKind::UnexpectedEof,
                    "encoded write unexpected length",
                )));
            },
            v => { dout!("encoded write ioctl wrote {}", v); },
        };

        remaining -= this_len;
        data_off += this_len;
        uncompressed_off += uncompressed_sz;
    }

    Ok(())
}

fn extract(src_path: &str, dst_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // TODO open() reads entire payload into pkg.content Vec
    // but for zero-copy it'd help to avoid it, e.g. hdr only:
    // PackageMetadata::parse(fs::File::open(src_path.as_ref()));
    let mut pkg = rpm::Package::open(src_path)?;
    let raw_pub_key = std::fs::read("test_assets/public_key.asc")?;
    pkg.verify_signature(Verifier::load_from_asc_bytes(&raw_pub_key)?)?;
    dout!("{} signature successfully verified", src_path);

    let hdr = &pkg.metadata.header;
    let pl_fmt = hdr.get_entry_data_as_string(IndexTag::RPMTAG_PAYLOADFORMAT)?;
    let pl_cmpr = hdr.get_entry_data_as_string(IndexTag::RPMTAG_PAYLOADCOMPRESSOR)?;
    let pl_flags = match hdr.get_entry_data_as_string(IndexTag::RPMTAG_PAYLOADFLAGS) {
        Ok(f) => f,
        Err(_) => "no flags",
    };
    dout!("payload: {} / {} / {}", pl_fmt, pl_cmpr, pl_flags);

    if pl_fmt == "cpio" && pl_cmpr == "zstd" {
        dout!("encoded I/O supported, processing payload at {}",
            pkg.metadata.get_package_segment_offsets().payload);
            encoded_copy_payload(&mut pkg.content, dst_path)?
    } else {
        // TODO reflink in place for uncompressed payload
        let seeklen = pkg.metadata.get_package_segment_offsets().payload;
        dout!("encoded I/O not supported");
        let mut srcf = std::fs::File::open(src_path)?;
        srcf.seek(std::io::SeekFrom::Current(seeklen.try_into().unwrap()))?;
        let mut dstf = std::fs::File::create(dst_path)?;

        let copied = std::io::copy(&mut srcf, &mut dstf)?;
        if copied != pkg.content.len().try_into().unwrap() {
            println!("data copy len {} doesn't match payload content len {}",
                copied, pkg.content.len());
                return Err(Box::new(Error::new(ErrorKind::UnexpectedEof,
                    "copy returned unexpected length",
                )));
        }
    }

    Ok(())
}

fn install_cpio(cpio_path: &str, inst_root: &str) -> Result<(), Box<dyn std::error::Error>> {
    dout!("installing");
    let mut file = std::io::BufReader::new(std::fs::File::open(cpio_path)?);
    loop {
        let mut reader = cpio::NewcReader::new(file).unwrap();
        if reader.entry().is_trailer() {
            break;
        }
        println!(
            "{} ({} bytes)",
            reader.entry().name(),
            reader.entry().file_size()
        );

        let inst_path = Path::new(inst_root).join(reader.entry().name());
        match inst_path.parent() {
            None => {},
            Some(p) => std::fs::create_dir_all(p)?,
        };

        // TODO handle all cpio types and set mode / owner

        if reader.entry().file_size() > 0 {
            let cpio_dataoff = reader.ioff()?;
            eprintln!("reader is at {}", cpio_dataoff);
            // we really shouldn't need to reopen per loop
            let mut copysrc = std::fs::OpenOptions::new()
                .read(true)
                .write(false)
                .open(cpio_path).unwrap();
            copysrc.seek(std::io::SeekFrom::Start(cpio_dataoff))?;
            let mut bound = copysrc.take(reader.entry().file_size().into());
            let mut entfile = std::fs::File::create(&inst_path).unwrap();
            match std::io::copy(&mut bound, &mut entfile) {
                Err(e) => {
                    eprintln!("failed to cpio file {} data", reader.entry().name());
                    return Err(Box::new(e));
                },
                Ok(l) => eprintln!("copied cpio file {} data len {}", inst_path.display(), l),
            };
        }
        // move to next
        file = reader.seek_finish().unwrap();
    }
    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 4 {
        usage(&args[0]);
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "invalid args")));
    }
    let rpm_path = &args[1];
    let cpio_path = &args[2];
    let inst_root = &args[3];
    extract(rpm_path, cpio_path)?;
    install_cpio(cpio_path, inst_root)?;
    Ok(())
}
