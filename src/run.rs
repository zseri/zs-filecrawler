use crate::{dbkeys, dbtrees, read_from_file, signals::*};
use crossbeam_channel as chan;
use digest::Digest;
use indicatif::ProgressBar;
use log::error;
use std::{convert::TryInto, io::Write, mem::drop, path::Path, time::Duration};

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

struct DoneQueueItem<'a> {
    file: &'a Path,
    msg: Vec<u8>,
}

fn worker<'a>(
    sigdat: &SignalDataUnArmed,
    hook: &Path,
    hook_hash: &sled::IVec,
    thashes: &sled::Tree,
    pb: ProgressBar,
    workqueue: chan::Receiver<&'a Path>,
    idnq: chan::Sender<DoneQueueItem<'a>>,
) {
    let mut hasher = sha2::Sha256::new();
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
                        if idnq
                            .send(DoneQueueItem {
                                file: f,
                                msg: format!("unable to open input file: {}", x).into_bytes(),
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
                let h = hasher.finalize_reset();
                drop(fh2);

                let h3 = hex::encode(&*h);
                let mut msg = Vec::new();

                if thashes
                    .get(&*h)
                    .expect("unable to retrieve hash data")
                    .as_ref()
                    != Some(hook_hash)
                {
                    use std::process as prc;
                    pb.set_message(&format!("hash {} file {}: run", h3, f.display()));

                    match prc::Command::new(hook)
                        .arg(&f)
                        .stdin(prc::Stdio::null())
                        .output()
                    {
                        Ok(mut x) if x.status.success() => {
                            thashes
                                .insert(&*h, hook_hash)
                                .expect("unable to update hash data");
                            x.stderr.extend_from_slice(&x.stdout[..]);
                            msg = x.stderr;
                        }
                        cmdres => {
                            msg = format!("HOOK failed with {:?}", cmdres).into_bytes();
                        }
                    }
                } else {
                    pb.set_message(&format!("hash {} file {}: skipped", h3, f.display()));
                }
                if idnq.send(DoneQueueItem { file: f, msg }).is_err() {
                    break;
                }
            }
        }
    }
    pb.finish();
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

    let thashes = db
        .open_tree(dbtrees::HASHES)
        .expect("unable to open hashes tree");
    let thashes = &thashes;

    let mut hasher = sha2::Sha256::new();
    hasher.update(&*read_from_file(hook).expect("unable to read hook file"));
    let hook_hash = sled::IVec::from(&*hasher.finalize_reset());
    let hook_hash = &hook_hash;

    let (iwq, workqueue) = chan::bounded(100 * wcnt);
    let (idnq, dnq) = chan::bounded::<DoneQueueItem>(100 * wcnt);
    let sigdat = sigdat.disarm_aquire();
    let sigdat = &sigdat;
    let mpbs = indicatif::MultiProgress::new();

    crossbeam_utils::thread::scope(move |s| {
        {
            let fpb = ProgressBar::new(fh.lines().count().try_into().unwrap());
            fpb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{prefix:.bold.dim} [{elapsed_precise}] {wide_bar} {pos}/{len} eta {eta}"),
            );
            fpb.set_prefix(" done ");
            let fpb = mpbs.add(fpb);
            s.spawn(move |_| {
                let mut stderr = std::io::stderr();
                while let Ok(x) = dnq.recv() {
                    if sigdat.got_ctrlc() {
                        break;
                    }
                    if !x.msg.is_empty() {
                        if let Ok(y) = std::str::from_utf8(&x.msg[..]) {
                            for i in y.trim().lines() {
                                fpb.println(format!("{}: {}", x.file.display(), i.trim()));
                            }
                        } else {
                            stderr
                                .write_all(format!("{}: ", x.file.display()).as_bytes())
                                .unwrap();
                            stderr.write_all(&x.msg[..]).unwrap();
                            stderr.write_all(b"\n").unwrap();
                            stderr.flush().unwrap();
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
            ipb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{prefix:.bold.dim} [{elapsed_precise}] {wide_bar} {pos}/{len}"),
            );
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
                    if ril.is_empty() || ril.bytes().next().unwrap() == b'#' || !rilp.is_file() {
                        idnq.send(DoneQueueItem {
                            file: rilp,
                            msg: Vec::new(),
                        })
                        .unwrap();
                        continue;
                    }
                    if does_exceed_max_filesize(rilp, max_filesize) {
                        idnq.send(DoneQueueItem {
                            file: rilp,
                            msg: "file is too big".to_string().into_bytes(),
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
            let idnq = idnq.clone();
            s.spawn(move |_| worker(sigdat, hook, hook_hash, thashes, pb, workqueue, idnq));
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
