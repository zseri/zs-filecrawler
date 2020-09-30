use crate::{misc::*, signals::*};
use crossbeam_channel as chan;
use digest::Digest;
use indicatif::ProgressBar;
use log::error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{convert::TryInto, io::Write, mem::drop, time::Duration};

struct DoneQueueItem<F> {
    file: F,
    msg: Vec<u8>,
    is_hookmsg: bool,
}

pub enum IngestList<'a> {
    IndexFile(&'a Path),
    GlobPattern(&'a str),
}

pub fn run(db: &sled::Db, sigdat: &SignalData, ingestl: IngestList<'_>) -> Result<(), sled::Error> {
    let max_filesize: Option<u64> = db.get(dbkeys::MAX_FSIZ)?.and_then(|iv| {
        let mut buf = [0u8; 8];
        if iv.len() != buf.len() {
            return None;
        }
        buf.copy_from_slice(&iv[..]);
        Some(u64::from_le_bytes(buf))
    });

    let wcnt: usize = 1 + if db.get(dbkeys::USE_MP)?.is_some() {
        num_cpus::get()
    } else {
        0
    };

    let hook = match db.get(dbkeys::HOOK)? {
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
    };
    let hook = hook.as_path();

    let dont_suppress = db.get(dbkeys::SUPPRESS_LOGMSGS)?.is_none();
    let logfile = match db.get(dbkeys::LOGFILE)? {
        None => None,
        Some(x) => {
            let x = std::str::from_utf8(&x[..]).expect("non utf-8 log file name");
            Some(
                std::fs::OpenOptions::new()
                    .read(false)
                    .append(true)
                    .create(true)
                    .open(x)?,
            )
        }
    };

    let thashes = db.open_tree(
        dbtrees::HASHES_
            .iter()
            .chain(sha2::Sha256::digest(&*read_from_file(hook)?).iter())
            .copied()
            .collect::<Vec<u8>>(),
    )?;

    match ingestl {
        IngestList::IndexFile(ingestf) => run_indexfile(
            &thashes,
            sigdat,
            max_filesize,
            wcnt,
            hook,
            dont_suppress,
            logfile,
            ingestf,
        ),
        IngestList::GlobPattern(glob_pattern) => run_globpat(
            &thashes,
            sigdat,
            max_filesize,
            wcnt,
            hook,
            dont_suppress,
            logfile,
            glob_pattern,
        ),
    }
}

fn worker<FilPath>(
    sigdat: &SignalDataUnArmed,
    hook: &Path,
    thashes: &sled::Tree,
    pb: ProgressBar,
    workqueue: chan::Receiver<FilPath>,
    dncnt: &AtomicU32,
    idnq: chan::Sender<DoneQueueItem<FilPath>>,
) where
    FilPath: std::convert::AsRef<Path>,
{
    let mut hasher = sha2::Sha256::new();
    while !sigdat.got_ctrlc() {
        pb.tick();

        let file = match workqueue.recv_timeout(Duration::from_secs(1)) {
            Ok(x) => x,
            Err(chan::RecvTimeoutError::Timeout) => continue,
            Err(chan::RecvTimeoutError::Disconnected) => break,
        };

        let far = file.as_ref();
        let fh2 = match read_from_file(far) {
            Ok(x) => x,
            Err(x) => {
                if idnq
                    .send(DoneQueueItem {
                        file,
                        msg: format!("unable to open input file: {}", x).into_bytes(),
                        is_hookmsg: false,
                    })
                    .is_err()
                {
                    break;
                }
                continue;
            }
        };
        let fdi = far.display();
        if fh2.len() > 40_960 {
            pb.set_message(&format!("file {}: calculate hash", fdi));
        }

        hasher.update(fh2.as_slice());
        let h = hasher.finalize_reset();
        drop(fh2);

        let h3 = hex::encode(&h);

        let msg = if thashes
            .get(&h)
            .expect("unable to retrieve hash data")
            .as_ref()
            .is_none()
        {
            pb.set_message(&format!("hash {} file {}: run", h3, far.display()));
            use std::process as prc;

            match prc::Command::new(hook)
                .arg(far)
                .stdin(prc::Stdio::null())
                .output()
            {
                Ok(mut x) if x.status.success() => {
                    thashes.insert(&h, &[]).expect("unable to update hash data");
                    x.stderr.extend_from_slice(&x.stdout[..]);
                    x.stderr
                }
                cmdres => format!("HOOK failed with {:?}", cmdres).into_bytes(),
            }
        } else {
            pb.set_message(&format!("hash {} file {}: skipped", h3, fdi));
            Vec::new()
        };
        if msg.is_empty() {
            dncnt.fetch_add(1, Ordering::SeqCst);
        } else if idnq
            .send(DoneQueueItem {
                file,
                msg,
                is_hookmsg: true,
            })
            .is_err()
        {
            break;
        }
    }
    pb.finish();
}

fn done_worker<FilPath, F>(
    sigdat: &SignalDataUnArmed,
    dont_suppress: bool,
    mut logfile: Option<std::fs::File>,
    fpb: indicatif::ProgressBar,
    dncnt: &AtomicU32,
    dnq: chan::Receiver<DoneQueueItem<FilPath>>,
    mut cntupd: F,
) where
    FilPath: std::convert::AsRef<Path>,
    F: FnMut(&indicatif::ProgressBar, u64) -> bool,
{
    let mut stderr = std::io::stderr();
    while !sigdat.got_ctrlc() {
        let has_done_file = match dnq.recv_timeout(Duration::from_secs(1)) {
            Ok(x) if !x.msg.is_empty() => {
                let fdi = x.file.as_ref().display();
                let premsg = logfile.as_ref().map(|_| {
                    format!(
                        "[{}] {}: ",
                        if x.is_hookmsg { "HOOK" } else { "INGEST" },
                        fdi
                    )
                });
                if let Ok(y) = std::str::from_utf8(&x.msg[..]) {
                    let y = y.trim();
                    if dont_suppress {
                        for i in y.lines() {
                            fpb.println(format!("{}: {}", fdi, i.trim()));
                        }
                    }
                    if let Some(log) = logfile.as_mut() {
                        let premsg = premsg.unwrap();
                        for i in y.lines() {
                            writeln!(log, "{}{}", premsg, i.trim()).unwrap();
                        }
                    }
                } else {
                    if dont_suppress {
                        stderr.write_all(format!("{}: ", fdi).as_bytes()).unwrap();
                        stderr.write_all(&x.msg[..]).unwrap();
                        stderr.write_all(b"\n").unwrap();
                        stderr.flush().unwrap();
                    }
                    if let Some(log) = logfile.as_mut() {
                        log.write_all(premsg.unwrap().as_bytes()).unwrap();
                        log.write_all(&x.msg[..]).unwrap();
                        log.write_all(b"\n").unwrap();
                        log.flush().unwrap();
                    }
                }
                true
            }
            Ok(_) => true,
            Err(chan::RecvTimeoutError::Disconnected) => break,
            Err(chan::RecvTimeoutError::Timeout) => false,
        };
        if !cntupd(
            &fpb,
            u64::from(dncnt.swap(0, Ordering::SeqCst)) + if has_done_file { 1 } else { 0 },
        ) {
            break;
        }
    }
    fpb.abandon();
}

fn does_exceed_max_filesize(fmd: &std::fs::Metadata, idx_max_filesize: Option<u64>) -> bool {
    if let Some(max_fsiz) = idx_max_filesize {
        if fmd.len() > max_fsiz {
            return true;
        }
    }
    false
}

fn run_indexfile(
    thashes: &sled::Tree,
    sigdat: &SignalData,
    max_filesize: Option<u64>,
    wcnt: usize,
    hook: &Path,
    dont_suppress: bool,
    logfile: Option<std::fs::File>,
    ingestf: &Path,
) -> Result<(), sled::Error> {
    if does_exceed_max_filesize(&std::fs::metadata(ingestf)?, max_filesize) {
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
    let fh = match std::str::from_utf8(&*fh) {
        Ok(x) => x,
        Err(x) => {
            error!("Unable to parse input file {}: {}", ingestf.display(), x);
            return Ok(());
        }
    };

    let (iwq, workqueue) = chan::bounded(4096 * wcnt);
    let (idnq, dnq) = chan::bounded::<DoneQueueItem<&Path>>(4096 * wcnt);
    let dncnt = AtomicU32::new(0);
    let dncnt = &dncnt;
    let sigdat = sigdat.disarm_aquire();
    let sigdat = &sigdat;
    let mpbs = indicatif::MultiProgress::new();

    crossbeam_utils::thread::scope(move |s| {
        {
            let fpb = ProgressBar::new(fh.lines().count().try_into().unwrap());
            fpb.set_style(indicatif::ProgressStyle::default_bar().template(
                "{prefix:.bold.dim} [{elapsed_precise}] {wide_bar} eta {eta} {pos}/{len}",
            ));
            fpb.set_prefix(" done ");
            let fpb = mpbs.add(fpb);

            s.spawn(move |_| {
                done_worker(
                    sigdat,
                    dont_suppress,
                    logfile,
                    fpb,
                    dncnt,
                    dnq,
                    move |fpb, delta| {
                        fpb.inc(delta);
                        fpb.position() != fpb.length()
                    },
                )
            });
        }

        {
            let idnq = idnq.clone();

            let ipb = ProgressBar::new(fh.lines().count().try_into().unwrap());
            ipb.set_style(indicatif::ProgressStyle::default_bar().template(
                "{prefix:.bold.dim} [{elapsed_precise}] {wide_bar} eta {eta} {pos}/{len}",
            ));
            ipb.set_prefix("ingest");
            let ipb = mpbs.add(ipb);
            let ips = ProgressBar::new_spinner();
            ips.set_style(
                indicatif::ProgressStyle::default_spinner()
                    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                    .template("{prefix:.bold.dim} {spinner} {wide_msg}"),
            );
            ips.set_prefix("ingest");
            let ips = mpbs.add(ips);

            s.spawn(move |_| {
                for ril in ipb.wrap_iter(fh.lines()) {
                    if sigdat.got_ctrlc() {
                        break;
                    }
                    let ril = ril.trim_start();
                    let file = Path::new(ril);
                    if ril.is_empty() || ril.bytes().next().unwrap() == b'#' {
                        dncnt.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                    let meta = match std::fs::metadata(file) {
                        Ok(x) => x,
                        Err(x) => {
                            idnq.send(DoneQueueItem {
                                file,
                                msg: format!("unable to read file metadata: {}", x).into_bytes(),
                                is_hookmsg: false,
                            })
                            .unwrap();
                            continue;
                        }
                    };
                    if !meta.is_file() {
                        dncnt.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                    if does_exceed_max_filesize(&meta, max_filesize) {
                        idnq.send(DoneQueueItem {
                            file,
                            msg: "file is too big".to_string().into_bytes(),
                            is_hookmsg: false,
                        })
                        .unwrap();
                        continue;
                    }
                    ips.set_message(ril);
                    if iwq.send(file).is_err() {
                        break;
                    }
                }
                ips.finish();
                ipb.abandon();
            });
        }

        let pbstyle = indicatif::ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner} {wide_msg}");

        for _ in 0..wcnt {
            let pb = indicatif::ProgressBar::new(0);
            pb.set_style(pbstyle.clone());
            let pb = mpbs.add(pb);
            let workqueue = workqueue.clone();
            let idnq = idnq.clone();
            s.spawn(move |_| worker(sigdat, hook, thashes, pb, workqueue, dncnt, idnq));
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

fn run_globpat(
    thashes: &sled::Tree,
    sigdat: &SignalData,
    max_filesize: Option<u64>,
    wcnt: usize,
    hook: &Path,
    dont_suppress: bool,
    logfile: Option<std::fs::File>,
    glob_pattern: &str,
) -> Result<(), sled::Error> {
    let paths = {
        let mut it = crate::misc::ShellwordSplitter::new(glob_pattern);

        let base = match it.next() {
            Some(Ok(x)) => x,
            _ => {
                eprintln!(
                    "ERROR: failed to parse 'run-glob' arguments, invalid invocation (base path)"
                );
                return Ok(());
            }
        };
        let base = std::path::Path::new(&*base);

        let patterns = match it.collect::<Result<Vec<_>, _>>() {
            Ok(x) => x,
            Err(_) => {
                eprintln!("ERROR: failed to parse 'run-glob' arguments, invalid invocation (pattern list)");
                return Ok(());
            }
        };

        match globwalk::GlobWalkerBuilder::from_patterns(base, &patterns[..])
            .file_type(globwalk::FileType::FILE)
            .build()
        {
            Ok(x) => x,
            Err(_) => {
                eprintln!("ERROR: failed to prepare the GlobWalker");
                return Ok(());
            }
        }
    };

    let (iwq, workqueue) = chan::bounded(1024 * wcnt);
    let (idnq, dnq) = chan::bounded::<DoneQueueItem<PathBuf>>(4096 * wcnt);
    let dncnt = AtomicU32::new(0);
    let dncnt = &dncnt;
    let sigdat = sigdat.disarm_aquire();
    let sigdat = &sigdat;
    let mpbs = indicatif::MultiProgress::new();

    crossbeam_utils::thread::scope(move |s| {
        {
            let fps = ProgressBar::new_spinner();
            fps.set_style(
                indicatif::ProgressStyle::default_spinner()
                    .template("{prefix:.bold.dim} [{elapsed_precise}] {spinner} {wide_msg}"),
            );
            fps.set_prefix(" done ");
            let fps = mpbs.add(fps);

            s.spawn(move |_| {
                let mut cnt: u64 = 0;
                done_worker(
                    sigdat,
                    dont_suppress,
                    logfile,
                    fps,
                    dncnt,
                    dnq,
                    move |fps, delta| {
                        cnt += delta;
                        fps.set_message(&format!("{}", cnt));
                        true
                    },
                )
            });
        }

        {
            let idnq = idnq.clone();

            let ips = ProgressBar::new_spinner();
            ips.set_style(
                indicatif::ProgressStyle::default_spinner()
                    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                    .template("{prefix:.bold.dim} [{elapsed_precise}] {spinner} {wide_msg}"),
            );
            ips.set_prefix("ingest");
            let ips = mpbs.add(ips);

            s.spawn(move |_| {
                for pathres in paths {
                    if sigdat.got_ctrlc() {
                        break;
                    }
                    let file = match pathres {
                        Ok(p) => p,
                        Err(e) => {
                            idnq.send(DoneQueueItem {
                                file: e.path().map(Path::to_path_buf).unwrap_or_else(PathBuf::new),
                                msg: format!("glob iter error: {}", e).into_bytes(),
                                is_hookmsg: false,
                            })
                            .unwrap();
                            continue;
                        }
                    };
                    let meta = match file.metadata() {
                        Ok(x) => x,
                        Err(x) => {
                            idnq.send(DoneQueueItem {
                                file: file.into_path(),
                                msg: format!("unable to read file metadata: {}", x).into_bytes(),
                                is_hookmsg: false,
                            })
                            .unwrap();
                            continue;
                        }
                    };
                    if !meta.is_file() {
                        continue;
                    }
                    if does_exceed_max_filesize(&meta, max_filesize) {
                        idnq.send(DoneQueueItem {
                            file: file.into_path(),
                            msg: "file is too big".to_string().into_bytes(),
                            is_hookmsg: false,
                        })
                        .unwrap();
                        continue;
                    }
                    ips.set_message(&format!("{}", file.path().display()));
                    if iwq.send(file.into_path()).is_err() {
                        break;
                    }
                }
                ips.abandon();
            });
        }

        let pbstyle = indicatif::ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner} {wide_msg}");

        for _ in 0..wcnt {
            let pb = indicatif::ProgressBar::new(0);
            pb.set_style(pbstyle.clone());
            let pb = mpbs.add(pb);
            let workqueue = workqueue.clone();
            let idnq = idnq.clone();
            s.spawn(move |_| worker(sigdat, hook, thashes, pb, workqueue, dncnt, idnq));
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
