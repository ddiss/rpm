use std::io::Write;
use zstd_safe;

use crate::errors::*;

/// Supported payload compression types.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum CompressionType {
    #[default]
    None,
    Gzip,
    Zstd,
    Xz,
    Bzip2,
}

impl std::str::FromStr for CompressionType {
    type Err = Error;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "gzip" => Ok(CompressionType::Gzip),
            "zstd" => Ok(CompressionType::Zstd),
            "xz" => Ok(CompressionType::Xz),
            "bzip2" => Ok(CompressionType::Bzip2),
            _ => Err(Error::UnknownCompressorType(raw.to_string())),
        }
    }
}

pub struct CompressorZstd {
    ctx: zstd_safe::CCtx<'static>,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    frame_max_content: usize,
}

pub enum Compressor {
    None(Vec<u8>),
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Zstd(CompressorZstd),
    Xz(xz2::write::XzEncoder<Vec<u8>>),
    Bzip2(bzip2::write::BzEncoder<Vec<u8>>),
}

impl TryFrom<CompressionWithLevel> for Compressor {
    type Error = Error;

    fn try_from(value: CompressionWithLevel) -> Result<Self, Self::Error> {
        match value {
            CompressionWithLevel::None => Ok(Compressor::None(Vec::new())),
            CompressionWithLevel::Gzip(level) => Ok(Compressor::Gzip(
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level)),
            )),
            CompressionWithLevel::Zstd(level) => {
                eprintln!("zstd cctx with level {}\n", level);
                let mut cctx = zstd_safe::CCtx::create();
                let _ = cctx.set_parameter(zstd_safe::CParameter::CompressionLevel(level));
                let _ = cctx.set_parameter(zstd_safe::CParameter::WindowLog(17));
                // Rpm checksums compressed and uncompressed data
                let _ = cctx.set_parameter(zstd_safe::CParameter::ChecksumFlag(false));
                // We need to know the uncompressed len for Btrfs encoded io
                // so we use ZSTD_compressStream2(..., ZSTD_e_end)
                // to ensure each zstd frame includes uncompressed len
                let _ = cctx.set_parameter(zstd_safe::CParameter::ContentSizeFlag(true));

                let cz = CompressorZstd{
                    ctx: cctx,
                    inbuf: Vec::new(),
                    outbuf: Vec::new(),
                    //frame_max_content: 0,   // no limit, regular stream
                    frame_max_content: 128 * 1024,   // limit; explicit framing
                };
                Ok(Compressor::Zstd(cz))
            },
            CompressionWithLevel::Xz(level) => Ok(Compressor::Xz(xz2::write::XzEncoder::new(
                Vec::new(),
                level,
            ))),
            CompressionWithLevel::Bzip2(level) => Ok(Compressor::Bzip2(
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(level)),
            )),
        }
    }
}

fn write_zstd_frames(cz: &mut CompressorZstd, content: &[u8], frame_max: usize) -> Result<usize, std::io::Error> {
    let iolen = content.len();
    // can be called by write or flush. write handles full frames while flush puts
    // any remainder in a single frame.
    assert!(frame_max <= cz.frame_max_content);

    // Maximum compressed size in worst case single-pass scenario
    let max_compressed_len = zstd_safe::compress_bound(frame_max);

    // append entire write to the input buffer
    cz.inbuf.extend_from_slice(content);

    // compress any entire frames that we may have
    let iter = cz.inbuf.chunks_exact(frame_max);
    let remainder = iter.remainder();
    for chunk in iter {
        let mut froutbuf = Vec::with_capacity(max_compressed_len);
        eprintln!("compressing {} byte chunk as zstd frame", frame_max);
        match cz.ctx.compress2(&mut froutbuf, chunk) {
            Err(e) => {
                // TODO rollback compressed?
                let es = zstd_safe::get_error_name(e);
                eprintln!("compress2() failed: {}", es);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, es));
            },
            Ok(l) => {
                eprintln!("compress2 returned: {} of frame_max {}",
                    l, frame_max);
                assert!(l == froutbuf.len());
                cz.outbuf.append(&mut froutbuf);
            }
        };
    }
    // any remainder must carry over to the next write / flush
    cz.inbuf = remainder.to_vec();
    Ok(iolen)
}

impl Write for Compressor {
    fn write(&mut self, content: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            Compressor::None(data) => data.write(content),
            Compressor::Gzip(encoder) => encoder.write(content),
            Compressor::Zstd(cz) => {
                assert!(cz.frame_max_content > 0);
                eprintln!("write of len {}", content.len());
                return write_zstd_frames(cz, content, cz.frame_max_content);
            },
            Compressor::Xz(encoder) => encoder.write(content),
            Compressor::Bzip2(encoder) => encoder.write(content),
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            Compressor::None(data) => data.flush(),
            Compressor::Gzip(encoder) => encoder.flush(),
            Compressor::Zstd(cz) => {
                assert!(cz.frame_max_content > 0);
                eprintln!("flush with {} inbuf", cz.inbuf.len());
                // no need to call ctx.flush_stream, ZSTD_e_end flushes.
                // write with frame_max = inbuf.len to flush any remainder
                return match write_zstd_frames(cz, &[], cz.inbuf.len()) {
                    Err(e) => Err(e),
                    Ok(_) => Ok(()),    // TODO map magic?
                };
            },
            Compressor::Xz(encoder) => encoder.flush(),
            Compressor::Bzip2(encoder) => encoder.flush(),
        }
    }
}

impl Compressor {
    pub(crate) fn finish_compression(self) -> Result<Vec<u8>, Error> {
        match self {
            Compressor::None(data) => Ok(data),
            Compressor::Gzip(encoder) => Ok(encoder.finish()?),
            Compressor::Zstd(cz) => {
                eprintln!("finishing zstd compressor");
                assert!(cz.frame_max_content > 0);
                // inbuf should have been flushed. XXX we could flush manually
                // here, but we have a non-mut self.
                assert!(cz.inbuf.len() == 0);
                return Ok(cz.outbuf);
                // Drop cctx calls ZSTD_freeCCtx()
            },
            Compressor::Xz(encoder) => Ok(encoder.finish()?),
            Compressor::Bzip2(encoder) => Ok(encoder.finish()?),
        }
    }

    pub(crate) fn set_frame_content_limit(self, max: usize) -> Result<(), Error> {
        match self {
            Compressor::Zstd(mut cz) => {
                // simplify: only allow frame clen changes if inbuf is empty
                assert!(cz.inbuf.len() == 0);
                cz.inbuf.reserve(2 * max);
                cz.frame_max_content = max;
                eprintln!("zstd frame content limit set: {}", max);
                Ok(())
            },
            // TODO: error code
            _ => Err(Error::UnknownCompressorType(
                    "set_frame_content_limit not supported".to_string()
                 )),
        }
    }
}

/// Supported compression types, with an associated compression level. This is used for setting
/// a custom compression configuration during RPM building.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionWithLevel {
    None,
    Zstd(i32),
    Gzip(u32),
    Xz(u32),
    Bzip2(u32),
}

impl CompressionWithLevel {
    pub(crate) fn compression_type(&self) -> CompressionType {
        match self {
            Self::None => CompressionType::None,
            Self::Gzip(_) => CompressionType::Gzip,
            Self::Zstd(_) => CompressionType::Zstd,
            Self::Xz(_) => CompressionType::Xz,
            Self::Bzip2(_) => CompressionType::Bzip2,
        }
    }
}

impl Default for CompressionWithLevel {
    fn default() -> Self {
        CompressionType::Gzip.into()
    }
}

impl From<CompressionType> for CompressionWithLevel {
    fn from(value: CompressionType) -> Self {
        match value {
            CompressionType::None => CompressionWithLevel::None,
            CompressionType::Gzip => CompressionWithLevel::Gzip(9),
            CompressionType::Xz => CompressionWithLevel::Xz(9),
            CompressionType::Zstd => CompressionWithLevel::Zstd(19),
            CompressionType::Bzip2 => CompressionWithLevel::Bzip2(9),
        }
    }
}
