#[cfg(feature = "signature-pgp")]
use rpm::{
    signature::pgp::{
        Signer,
    },
};
use std::io::{
    Error,
    ErrorKind,
};

#[cfg(debug_assertions)]
macro_rules! dout {
    ($($l:tt)*) => { println!($($l)*); }
}
#[cfg(not(debug_assertions))]
macro_rules! dout {
    ($($l:tt)*) => {};
}

fn archive_padlen(off: usize, alignment: usize) -> usize {
    (alignment - (off & (alignment - 1))) % alignment
}

// our goal is to place data at a 4k aligned offset
const NEWC_DATA_ALIGN_GOAL: usize = 4096;
// the newc header len, without path or padding
const NEWC_HDR_LEN: usize = 110;
fn hdr_fname_align(path: &str) -> String {
    let cur_dataoff = NEWC_HDR_LEN + path.len() + 1; // +1 for nullterm
    if cur_dataoff > NEWC_DATA_ALIGN_GOAL {
        eprintln!("{} no space left for alignment", path);
        return path.to_string();
    }
    let padlen = archive_padlen(cur_dataoff, NEWC_DATA_ALIGN_GOAL);
    // FIXME not sure why we're out / ah, because the file path is prefixed with .
    // not needed when we take it into account
    //padlen -= 1;
    //let pad = NEWC_DATA_ALIGN_GOAL - cur_dataoff;
    let mut p = path.as_bytes().to_vec();
    let mut z = vec![0u8; padlen.try_into().unwrap()];
    p.append(&mut z);
    String::from_utf8(p).unwrap()
}

fn create(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let raw_secret_key = std::fs::read("./test_assets/secret_key.asc")?;
    // It's recommended to use timestamp of last commit in your VCS
    let source_date = 1_600_000_000;
    let padded_fname = hdr_fname_align("./usr/bin/vim-nox11");
    let pkg = rpm::PackageBuilder::new("vim-encodedio-poc", "9.1", "Vim", "x86_64",
                                       "vim-nox11 binary packed with aligned cpio and zstd frames")
        .compression(rpm::CompressionWithLevel::Zstd(15))
        //.compression(rpm::CompressionType::Gzip)
        //.compression(rpm::CompressionType::None)
        .with_file(
            "/usr/bin/vim-nox11",
            rpm::FileOptions::new(padded_fname),
        )?
        .pre_install_script("echo preinst")
        // If you don't need reproducible builds,
        // you can remove the following line
        .source_date(source_date)
        .build_host("mybuildhost")
        .add_changelog_entry(
            "Max Mustermann <max@example.com> - 0.1-29",
            "- was awesome, eh?",
            1_681_411_811,
        )
        .add_changelog_entry(
            "Charlie Yom <test2@example.com> - 0.1-28",
            "- yeah, it was",
            // Raw timestamp for 1996-08-14 05:20:00
            840_000_000,
        )
        .requires(rpm::Dependency::any("vim-data-common"))
        .vendor("openSUSE")
        .url("https://www.vim.org/")
        .vcs("git:repo=example_repo:branch=example_branch:sha=example_sha")
        .build_and_sign(Signer::load_from_asc_bytes(&raw_secret_key)?)?;
    let mut f = std::fs::File::create(path)?;
    pkg.write(&mut f)?;
    dout!("package written to {}, payload at {}", path,
        pkg.metadata.get_package_segment_offsets().payload);
    Ok(())
}

fn usage(prog: &String) {
    println!("usage: {} rpm-path", prog);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        usage(&args[0]);
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "invalid args")));
    }
    create(&args[1])?;
    Ok(())
}
