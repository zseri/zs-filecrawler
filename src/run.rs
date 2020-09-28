use crate::{dbkeys, dbtrees, read_from_file, signals::*};
use crossbeam_channel as chan;
use digest::Digest;
use indicatif::ProgressBar;
use log::error;
use std::{convert::TryInto, io::Write, mem::drop, path::Path, time::Duration};

struct DoneQueueItem<'a> {
    file: &'a Path,
    msg: Vec<u8>,
    is_hookmsg: bool,
}

struct HashQueueItem<'a> {
    file: &'a Path,
    hash: [u8; 32],
    h3: String,
}

fn worker<'a>(
    sigdat: &SignalDataUnArmed,
    hook: &Path,
    thashes: &sled::Tree,
    pb: ProgressBar,
    workqueue: chan::Receiver<&'a Path>,
    hsqs: chan::Sender<HashQueueItem<'a>>,
    hsqr: chan::Receiver<HashQueueItem<'a>>,
    idnq: chan::Sender<DoneQueueItem<'a>>,
) {
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
                let fh2 = match read_from_file(&f) {
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
                if fh2.len() > 40_960 {
                    pb.set_message(&format!("file {}: calculate hash", f.display()));
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
                    pb.set_message(&format!("hash {} file {}: skipped", h3, f.display()));
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
                use std::process as prc;
                pb.set_message(&format!("hash {} file {}: run", h3, file.display()));

                let msg: Vec<_> = match prc::Command::new(hook)
                    .arg(&file)
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

pub fn run(db: &sled::Db, sigdat: &SignalData, ingestf: &Path) -> Result<(), sled::Error> {
    let max_filesize: Option<u64> = db.get(dbkeys::MAX_FSIZ)?.and_then(|iv| {
        let mut buf = [0u8; 8];
        if iv.len() != buf.len() {
            return None;
        }
        buf.copy_from_slice(&iv[..]);
        Some(u64::from_le_bytes(buf))
    });

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

    let mut hasher = sha2::Sha256::new();
    hasher.update(&*read_from_file(hook)?);
    let hook_hash = sled::IVec::from(&*hasher.finalize_reset());
    let hook_hash = &hook_hash;

    let thashes: Vec<u8> = dbtrees::HASHES_
        .iter()
        .chain(hook_hash.iter())
        .map(|i| *i)
        .collect();
    let thashes = db.open_tree(thashes)?;
    let thashes = &thashes;

    let dont_suppress = db.get(dbkeys::SUPPRESS_LOGMSGS)?.is_none();
    let mut logfile = match db.get(dbkeys::LOGFILE)? {
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

    let (iwq, workqueue) = chan::bounded(4096 * wcnt);
    let (hsqs, hsqr) = chan::bounded::<HashQueueItem>(4096 * wcnt);
    let (idnq, dnq) = chan::bounded::<DoneQueueItem>(1024 * wcnt);
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
                                file: rilp,
                                msg: format!("unable to read file metadata: {}", x).into_bytes(),
                                is_hookmsg: false,
                            })
                            .unwrap();
                            continue;
                        }
                    };
                    if !meta.is_file() {
                        idnq.send(DoneQueueItem {
                            file: rilp,
                            msg: Vec::new(),
                            is_hookmsg: false,
                        })
                        .unwrap();
                        continue;
                    }
                    if does_exceed_max_filesize(&meta, max_filesize) {
                        idnq.send(DoneQueueItem {
                            file: rilp,
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
