mod signals;

use crate::signals::*;
use digest::Digest;
use indoc::indoc;
use log::error;
use std::{
    convert::TryInto,
    io::{BufRead, Write},
    mem::drop,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use text_io::read;

mod dbkeys {
    pub const HOOK: &[u8] = b"hook";
    pub const MAX_FSIZ: &[u8] = b"max-filesize";
    pub const USE_MP: &[u8] = b"use-mp";
}

mod dbtrees {
    pub const HASHES: &[u8] = b"hashes";
}

fn logger_init() {
    use simplelog::*;
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
    )])
    .unwrap();
}

fn split_command(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(pos) => (&line[..pos], &line[pos + 1..]),
        None => (line, ""),
    }
}

fn read_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<readfilez::FileHandle> {
    readfilez::read_from_file(std::fs::File::open(path))
}

fn handle_dbres<T>(x: Result<T, sled::Error>) -> Option<T> {
    x.map_err(|e| {
        error!("{}", e);
    })
    .ok()
}

fn does_exceed_max_filesize(filename: &Path, idx_max_filesize: Option<u64>) -> bool {
    if let Some(max_fsiz) = idx_max_filesize {
        if let Ok(fmd) = std::fs::metadata(filename) {
            if fmd.len() > max_fsiz {
                return true;
            }
        }
    }
    false
}

fn run(db: &sled::Db, sigdat: &SignalData, ingestf: &Path) -> Result<(), sled::Error> {
    use crossbeam_channel as chan;
    use indicatif::ProgressBar;

    let max_filesize: Option<u64> = db.get(dbkeys::MAX_FSIZ)?.and_then(|iv| {
        let mut buf = [0u8; 8];
        if iv.len() != buf.len() {
            return None;
        }
        buf.copy_from_slice(&iv[..]);
        Some(u64::from_le_bytes(buf))
    });

    if does_exceed_max_filesize(ingestf, max_filesize) {
        error!("File is too big: {}", ingestf.display());
        return Ok(());
    }

    let fh = match read_from_file(ingestf) {
        Ok(x) => x,
        Err(x) => {
            error!("Unable to open input file {}: {}", ingestf.display(), x);
            return Ok(());
        }
    };

    let wcnt: usize = 1 + if db.get(dbkeys::USE_MP)?.is_some() {
        num_cpus::get()
    } else {
        0
    };

    let hook = Arc::new(match db.get(dbkeys::HOOK)? {
        Some(h) => {
            let p = match std::str::from_utf8(&*h) {
                Ok(x) => Path::new(x),
                Err(x) => {
                    error!("Invalid hook in DB (non-utf8): error = {}", x);
                    return Ok(());
                }
            };
            if !p.is_file() {
                error!("Hook not found: {}", p.display());
                return Ok(());
            }
            p.to_path_buf()
        }
        None => {
            error!("No hook set!");
            return Ok(());
        }
    });

    let mut hasher = sha2::Sha256::new();
    hasher.update(&*read_from_file(hook.as_path()).expect("unable to read hook file"));
    let hook_hash = sled::IVec::from(&*hasher.finalize_reset());

    let (iwq, workqueue) = chan::bounded(100 * wcnt);
    let (idnq, dnq) = chan::bounded(1000 * wcnt);
    let sigdat = Arc::new(sigdat.disarm_aquire());
    let mpbs = indicatif::MultiProgress::new();

    crossbeam_utils::thread::scope(move |s| {
        {
            let sigdat = sigdat.clone();
            let fpb = ProgressBar::new(fh.lines().count().try_into().unwrap());
            fpb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{prefix:.bold.dim} {wide_bar} {pos}/{len}"),
            );
            fpb.set_prefix(" done ");
            let fpb = mpbs.add(fpb);
            s.spawn(move |_| {
                while let Ok(x) = dnq.recv() {
                    if sigdat.got_ctrlc() {
                        break;
                    }
                    if x {
                        fpb.inc(1);
                    } else {
                        fpb.set_length(fpb.length() - 1);
                    }
                    if fpb.is_finished() {
                        break;
                    }
                }
                fpb.abandon();
            });
        }

        {
            let sigdat = sigdat.clone();
            let idnq = idnq.clone();

            let ipb = ProgressBar::new(fh.lines().count().try_into().unwrap());
            ipb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{prefix:.bold.dim} {wide_bar} {pos}/{len}"),
            );
            ipb.set_prefix("ingest");
            let ipb = mpbs.add(ipb);
            let ips = ProgressBar::new_spinner();
            ips.set_style(
                indicatif::ProgressStyle::default_spinner()
                    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                    .template("[{elapsed_precise}] {prefix:.bold.dim} {spinner} {wide_msg}"),
            );
            ips.set_prefix("ingest");
            let ips = mpbs.add(ips);

            s.spawn(move |_| {
                for ingline in ipb.wrap_iter(fh.lines()) {
                    if sigdat.got_ctrlc() {
                        break;
                    }
                    if let Err(x) = &ingline {
                        ips.println(format!("Got invalid line: ERROR: {}", x));
                        idnq.send(false).unwrap();
                        continue;
                    }
                    let ril = ingline.unwrap();
                    let ril = ril.trim_start();
                    if ril.is_empty()
                        || ril.bytes().next().unwrap() == b'#'
                        || !Path::new(ril).is_file()
                    {
                        idnq.send(false).unwrap();
                        continue;
                    }
                    if does_exceed_max_filesize(Path::new(ril), max_filesize) {
                        ips.println(format!("File is too big: {}", ril));
                        idnq.send(false).unwrap();
                        continue;
                    }
                    ips.set_message(ril);
                    if iwq.send(Path::new(ril).to_path_buf()).is_err() {
                        break;
                    }
                }
                ips.finish();
                ipb.abandon();
            });
        }

        let thashes = db
            .open_tree(dbtrees::HASHES)
            .expect("unable to open hashes tree");

        let pbstyle = indicatif::ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner} {wide_msg}");

        for _ in 0..wcnt {
            let sigdat = sigdat.clone();
            let pb = indicatif::ProgressBar::new(0);
            pb.set_style(pbstyle.clone());
            let pb = mpbs.add(pb);
            let workqueue = workqueue.clone();
            let idnq = idnq.clone();
            let thashes = thashes.clone();
            let hook = hook.clone();
            let hook_hash = hook_hash.clone();
            let mut hasher = sha2::Sha256::new();
            s.spawn(move |_| {
                loop {
                    if sigdat.got_ctrlc() {
                        pb.abandon();
                        break;
                    }
                    pb.tick();
                    match workqueue.recv_timeout(Duration::from_secs(1)) {
                        Err(chan::RecvTimeoutError::Timeout) => continue,
                        Err(chan::RecvTimeoutError::Disconnected) => break,

                        Ok(f) => {
                            let fh2 = match read_from_file(&f) {
                                Ok(x) => x,
                                Err(x) => {
                                    pb.println(format!(
                                        "Unable to open input file {}: {}",
                                        f.display(),
                                        x
                                    ));
                                    if idnq.send(false).is_err() {
                                        break;
                                    }
                                    continue;
                                }
                            };
                            if fh2.len() > 40_960 {
                                pb.set_message(&format!("file {}: calculate hash", f.display()));
                            }
                            hasher.update(fh2.as_slice());
                            let h = hasher.finalize_reset();
                            drop(fh2);

                            let h3 = hex::encode(&*h);

                            if thashes
                                .get(&*h)
                                .expect("unable to retrieve hash data")
                                .as_ref()
                                != Some(&hook_hash)
                            {
                                use std::process as prc;
                                pb.set_message(&format!("hash {} file {}: run", h3, f.display()));

                                match prc::Command::new(hook.as_path())
                                    .arg(&f)
                                    .stdin(prc::Stdio::null())
                                    .output()
                                {
                                    Ok(mut x) if x.status.success() => {
                                        thashes
                                            .insert(&*h, hook_hash.clone())
                                            .expect("unable to update hash data");
                                        x.stderr.extend_from_slice(&x.stdout[..]);
                                        if let Ok(x) = std::str::from_utf8(&x.stderr) {
                                            for i in x.lines() {
                                                pb.println(i);
                                            }
                                        } else {
                                            let mut stderr = std::io::stderr();
                                            stderr.write_all(&x.stderr).unwrap();
                                        }
                                    }
                                    cmdres => {
                                        pb.println(format!(
                                            "{}, HOOK failed with {:?}",
                                            f.display(),
                                            cmdres
                                        ));
                                    }
                                }
                            } else {
                                pb.set_message(&format!(
                                    "hash {} file {}: skipped",
                                    h3,
                                    f.display()
                                ));
                            }
                            if idnq.send(true).is_err() {
                                break;
                            }
                        }
                    }
                }
                pb.finish();
            });
        }
        drop(workqueue);
        drop(idnq);
        mpbs.join().unwrap();
    })
    .map_err(|_| {
        sled::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "run terminated unexpectedly",
        ))
    })
}

fn main() {
    logger_init();

    let sigdat = Arc::new(SignalDataIntern::new());
    register_signal_handlers(sigdat.clone());

    let mut stdout = std::io::stdout();
    let mut dbpath = PathBuf::from("zsfc-progstate");

    if let Some(dbf) = std::env::args().nth(1) {
        if dbf == "--help" {
            writeln!(stdout, "USAGE: zs-filecrawler [DB_PATH]").unwrap();
            std::process::exit(0);
        }
        dbpath = dbf.into()
    }

    let dbt = sled::Config::new()
        .path(dbpath)
        .mode(sled::Mode::HighThroughput)
        .cache_capacity(1_048_576)
        .use_compression(true)
        .compression_factor(5)
        .open()
        .expect("unable to open database");

    let thashes = dbt
        .open_tree(dbtrees::HASHES)
        .expect("unable to open hash² map");

    loop {
        // disable catching of Ctrl-C
        sigdat.set_ctrlc_armed(true);
        write!(stdout, "zs-filecrawler >> ").unwrap();
        stdout.flush().unwrap();

        let line: String = read!("{}\n");
        let line = line.trim();

        match line {
            "exit" | "quit" => {
                handle_dbres(thashes.flush());
                handle_dbres(dbt.flush());
                break;
            }
            "help" => {
                println!(
                    "{}",
                    indoc!(
                        "
                        Commands:
                        exit | quit      exit this program without saving
                        clear            clear the hash² db table
                        dprint           print the hash² db table
                        flush            sync db data to disk

                        set-max-filesize SIZ|none
                                         skip any file with a length greater than SIZ
                        use-mp y|n       enable/disable parallel hook runs
                        set-hook FILE    set used hook (USAGE: ./hook.sh PATH)
                        run FILE         process files from index, read file paths from FILE
                                         (advice: use absolute paths)
                                         This processing is interruptable with Ctrl+C.

                        If you want to set the database path, you must specify it
                            as the first command line argument to zs-filecrawler.
                        "
                    )
                );
            }
            "clear" => {
                handle_dbres(thashes.clear());
            }
            "dprint" => {
                for x in thashes.iter() {
                    if let Some((k, v)) = handle_dbres(x) {
                        println!("{} via {}", hex::encode(&*k), hex::encode(&*v));
                    }
                }
            }
            "flush" => {
                handle_dbres(thashes.flush());
                handle_dbres(dbt.flush());
            }
            _ => {
                let (cmd, rest) = split_command(line);
                let rest = rest.trim();
                if rest.is_empty() {
                    error!("No input file given or unknown command!");
                    continue;
                }
                match cmd {
                    "use-mp" => {
                        handle_dbres(match rest {
                            "Y" | "y" | "yes" => dbt.insert(dbkeys::USE_MP, &[]),
                            "N" | "n" | "no" => dbt.remove(dbkeys::USE_MP),
                            _ => {
                                error!("unknown specifier");
                                continue;
                            }
                        });
                    }
                    "set-hook" => {
                        handle_dbres(dbt.insert(dbkeys::HOOK, rest));
                    }
                    "set-max-filesize" => {
                        if rest == "none" {
                            handle_dbres(dbt.remove(dbkeys::MAX_FSIZ));
                            continue;
                        }
                        let bytes_cnt = match byte_unit::Byte::from_str(rest) {
                            Err(x) => {
                                error!("Got invalid byte unit value: {}: {:?}", rest, x);
                                continue;
                            }
                            Ok(x) => x.get_bytes(),
                        };
                        if bytes_cnt >= (isize::max_value() as u128) {
                            error!("Given byte unit value is too big: {}", rest);
                            continue;
                        }
                        handle_dbres(
                            dbt.insert(dbkeys::MAX_FSIZ, &(bytes_cnt as u64).to_le_bytes()),
                        );
                    }
                    "run" => {
                        handle_dbres(run(&dbt, &sigdat, Path::new(rest)));
                    }
                    _ => {
                        error!("Unknown command!");
                    }
                }
            }
        }
    }
}
