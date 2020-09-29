use crate::{misc::*, signals::*};
use crossbeam_channel as chan;
use digest::Digest;
use indicatif::ProgressBar;
use log::error;
use std::path::{Path, PathBuf};
use std::{convert::TryInto, io::Write, mem::drop, time::Duration};

struct DoneQueueItem<F> {
    file: F,
    msg: Vec<u8>,
    is_hookmsg: bool,
}

struct HashQueueItem<F> {
    file: F,
    hash: [u8; 32],
    h3: String,
}

pub enum IngestList<'a> {
    IndexFile(&'a Path),
    GlobPattern(&'a str),
}

fn worker<FilPath>(
    sigdat: &SignalDataUnArmed,
    hook: &Path,
    thashes: &sled::Tree,
    pb: ProgressBar,
    workqueue: chan::Receiver<FilPath>,
    hsqs: chan::Sender<HashQueueItem<FilPath>>,
    hsqr: chan::Receiver<HashQueueItem<FilPath>>,
    idnq: chan::Sender<DoneQueueItem<FilPath>>,
) where
    FilPath: std::convert::AsRef<Path>,
{
    let mut hasher = sha2::Sha256::new();
    loop {
        if sigdat.got_ctrlc() {
            pb.abandon();
            break;
        }
        pb.tick();
        chan::select! {
            recv(workqueue) -> msg => {
                let f = match msg {
                    Ok(msg) => msg,
                    Err(_) => break,
                };
                let far = f.as_ref();
                let fh2 = match read_from_file(far) {
                    Ok(x) => x,
                    Err(x) => {
                        if idnq
                            .send(DoneQueueItem {
                                file: f,
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
                let h: [u8; 32] = hasher
                    .finalize_reset()
                    .as_slice()
                    .try_into()
                    .expect("hash algo has unexpected hash result size");
                drop(fh2);

                let h3 = hex::encode(&h);

                if thashes
                    .get(&h)
                    .expect("unable to retrieve hash data")
                    .as_ref()
                    .is_none()
                {
                    hsqs.send(HashQueueItem {
                        file: f,
                        hash: h,
                        h3,
                    }).unwrap();
                } else {
                    pb.set_message(&format!("hash {} file {}: skipped", h3, fdi));
                    if idnq
                        .send(DoneQueueItem {
                            file: f,
                            msg: Vec::new(),
                            is_hookmsg: true,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }

            recv(hsqr) -> msg => {
                let HashQueueItem { file, hash, h3 } = msg.unwrap();
                let far = file.as_ref();
                use std::process as prc;
                pb.set_message(&format!("hash {} file {}: run", h3, far.display()));

                let msg: Vec<_> = match prc::Command::new(hook)
                    .arg(far)
                    .stdin(prc::Stdio::null())
                    .output()
                {
                    Ok(mut x) if x.status.success() => {
                        thashes
                            .insert(&hash, &[])
                            .expect("unable to update hash data");
                        x.stderr.extend_from_slice(&x.stdout[..]);
                        x.stderr
                    }
                    cmdres => format!("HOOK failed with {:?}", cmdres).into_bytes(),
                };
                if idnq
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

            default(Duration::from_secs(1)) => continue,
        }
    }
    pb.finish();
}

fn does_exceed_max_filesize(fmd: &std::fs::Metadata, idx_max_filesize: Option<u64>) -> bool {
    if let Some(max_fsiz) = idx_max_filesize {
        if fmd.len() > max_fsiz {
            return true;
        }
    }
    false
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

fn run_indexfile(
    thashes: &sled::Tree,
    sigdat: &SignalData,
    max_filesize: Option<u64>,
    wcnt: usize,
    hook: &Path,
    dont_suppress: bool,
    mut logfile: Option<std::fs::File>,
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
    let (hsqs, hsqr) = chan::bounded::<HashQueueItem<&Path>>(4096 * wcnt);
    let (idnq, dnq) = chan::bounded::<DoneQueueItem<&Path>>(1024 * wcnt);
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
                let mut stderr = std::io::stderr();
                while let Ok(x) = dnq.recv() {
                    if sigdat.got_ctrlc() {
                        break;
                    }
                    if !x.msg.is_empty() {
                        let premsg = logfile.as_ref().map(|_| {
                            format!(
                                "[{}] {}: ",
                                if x.is_hookmsg { "HOOK" } else { "INGEST" },
                                x.file.display()
                            )
                        });
                        if let Ok(y) = std::str::from_utf8(&x.msg[..]) {
                            let y = y.trim();
                            if dont_suppress {
                                for i in y.lines() {
                                    fpb.println(format!("{}: {}", x.file.display(), i.trim()));
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
                                stderr
                                    .write_all(format!("{}: ", x.file.display()).as_bytes())
                                    .unwrap();
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
                    }
                    fpb.inc(1);
                    if fpb.position() == fpb.length() {
                        break;
                    }
                }
                fpb.abandon();
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
                    let rilp = Path::new(ril);
                    if ril.is_empty() || ril.bytes().next().unwrap() == b'#' {
                        idnq.send(DoneQueueItem {
                            file: rilp,
                            msg: Vec::new(),
                            is_hookmsg: false,
                        })
                        .unwrap();
                        continue;
                    }
                    let meta = match std::fs::metadata(rilp) {
                        Ok(x) => x,
                        Err(x) => {
                            idnq.send(DoneQueueItem {
                                file: rilp.into(),
                                msg: format!("unable to read file metadata: {}", x).into_bytes(),
                                is_hookmsg: false,
                            })
                            .unwrap();
                            continue;
                        }
                    };
                    if !meta.is_file() {
                        idnq.send(DoneQueueItem {
                            file: rilp.into(),
                            msg: Vec::new(),
                            is_hookmsg: false,
                        })
                        .unwrap();
                        continue;
                    }
                    if does_exceed_max_filesize(&meta, max_filesize) {
                        idnq.send(DoneQueueItem {
                            file: rilp.into(),
                            msg: "file is too big".to_string().into_bytes(),
                            is_hookmsg: false,
                        })
                        .unwrap();
                        continue;
                    }
                    ips.set_message(ril);
                    if iwq.send(rilp).is_err() {
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
            let hsqs = hsqs.clone();
            let hsqr = hsqr.clone();
            let idnq = idnq.clone();
            s.spawn(move |_| worker(sigdat, hook, thashes, pb, workqueue, hsqs, hsqr, idnq));
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
    mut logfile: Option<std::fs::File>,
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
    let (hsqs, hsqr) = chan::bounded::<HashQueueItem<PathBuf>>(4096 * wcnt);
    let (idnq, dnq) = chan::bounded::<DoneQueueItem<PathBuf>>(1024 * wcnt);
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
                let mut stderr = std::io::stderr();
                let mut cnt: u64 = 0;
                while let Ok(x) = dnq.recv() {
                    if sigdat.got_ctrlc() {
                        break;
                    }
                    if !x.msg.is_empty() {
                        let premsg = logfile.as_ref().map(|_| {
                            format!(
                                "[{}] {}: ",
                                if x.is_hookmsg { "HOOK" } else { "INGEST" },
                                x.file.display()
                            )
                        });
                        if let Ok(y) = std::str::from_utf8(&x.msg[..]) {
                            let y = y.trim();
                            if dont_suppress {
                                for i in y.lines() {
                                    fps.println(format!("{}: {}", x.file.display(), i.trim()));
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
                                stderr
                                    .write_all(format!("{}: ", x.file.display()).as_bytes())
                                    .unwrap();
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
                    }
                    cnt += 1;
                    fps.set_message(&format!("{}", cnt));
                    fps.tick();
                }
                fps.abandon();
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
                    let rilp = match pathres {
                        Ok(p) => p,
                        Err(e) => {
                            idnq.send(DoneQueueItem {
                                file: e
                                    .path()
                                    .map(Path::to_path_buf)
                                    .unwrap_or(PathBuf::from("")),
                                msg: format!("glob iter error: {}", e).into_bytes(),
                                is_hookmsg: false,
                            })
                            .unwrap();
                            continue;
                        }
                    };
                    let meta = match rilp.metadata() {
                        Ok(x) => x,
                        Err(x) => {
                            idnq.send(DoneQueueItem {
                                file: rilp.into_path(),
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
                            file: rilp.into_path(),
                            msg: "file is too big".to_string().into_bytes(),
                            is_hookmsg: false,
                        })
                        .unwrap();
                        continue;
                    }
                    ips.set_message(&format!("{}", rilp.path().display()));
                    if iwq.send(rilp.into_path()).is_err() {
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
            let hsqs = hsqs.clone();
            let hsqr = hsqr.clone();
            let idnq = idnq.clone();
            s.spawn(move |_| worker(sigdat, hook, thashes, pb, workqueue, hsqs, hsqr, idnq));
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
