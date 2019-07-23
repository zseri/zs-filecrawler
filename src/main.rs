#[macro_use]
extern crate log;

use digest::Digest;
use generic_array::{typenum::U32, GenericArray};
use hashbrown::{HashMap, HashSet};
use indoc::indoc;
use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use text_io::{read, try_read, try_scan};

fn logger_init() {
    use simplelog::*;
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
    )
    .unwrap()])
    .unwrap();
}

struct SignalDataIntern {
    ctrlc: AtomicBool,
    ctrlc_armed: AtomicBool,
}
type SignalData = Arc<SignalDataIntern>;

impl SignalDataIntern {
    pub fn got_ctrlc(&self) -> bool {
        self.ctrlc.load(Ordering::SeqCst)
    }
    pub fn set_ctrlc(&self, val: bool) {
        self.ctrlc.store(val, Ordering::SeqCst);
    }
    pub fn is_ctrlc_armed(&self) -> bool {
        self.ctrlc_armed.load(Ordering::SeqCst)
    }
    pub fn set_ctrlc_armed(&self, val: bool) {
        self.ctrlc_armed.store(val, Ordering::SeqCst);
    }
}

fn register_signal_handlers(dat: SignalData) {
    unsafe {
        signal_hook::register(signal_hook::SIGINT, move || {
            if dat.is_ctrlc_armed() {
                std::process::exit(128 + signal_hook::SIGINT);
            } else {
                dat.set_ctrlc(true);
            }
        })
    }
    .or_else(|e| {
        warn!("Failed to register for SIGINT {:?}", e);
        Err(e)
    })
    .ok();
}

fn split_command(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(pos) => (&line[..pos], &line[pos + 1..]),
        None => (line, ""),
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
struct IndexEntry {
    is_fin: bool,
    paths: HashSet<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
struct ProgStateDetail {
    hook: PathBuf,
    idxd: HashMap<GenericArray<u8, U32>, IndexEntry>,
}

#[derive(Clone, Debug)]
struct ProgState {
    sfile: PathBuf,
    detail: ProgStateDetail,
    modified: bool,
}

fn read_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<readfilez::FileHandle> {
    readfilez::read_from_file(std::fs::File::open(path))
}

impl ProgState {
    fn load_from_sfile(&mut self) -> Result<(), String> {
        let fh = read_from_file(&self.sfile)
            .map_err(|x| format!("Unable to open sfile ({}: {})", self.sfile.display(), x))?;
        let z = flate2::read::DeflateDecoder::new(fh.as_slice());
        self.detail = bincode::deserialize_from(z)
            .map_err(|x| format!("Unable to read sfile ({}: {})", self.sfile.display(), x))?;
        self.modified = false;
        Ok(())
    }

    fn save_to_sfile(&mut self) -> Result<(), String> {
        let fh = std::fs::File::create(&self.sfile)
            .map_err(|x| format!("Failed to create sfile ({}: {})", self.sfile.display(), x))?;
        let z = flate2::write::DeflateEncoder::new(fh, flate2::Compression::default());
        bincode::serialize_into(z, &self.detail)
            .map_err(|x| format!("Failed to write sfile ({}: {})", self.sfile.display(), x))?;
        self.modified = false;
        Ok(())
    }

    fn idx_gc(&mut self) {
        self.modified = true;
        self.detail.idxd.retain(|_, ixe| {
            ixe.paths.retain(|f| Path::new(f).is_file());
            !ixe.paths.is_empty()
        });
    }
}

fn main() {
    logger_init();

    let sigdat = Arc::new(SignalDataIntern {
        ctrlc: AtomicBool::new(false),
        ctrlc_armed: AtomicBool::new(true),
    });
    register_signal_handlers(sigdat.clone());

    let mut stdout = std::io::stdout();

    let mut pstate = ProgState {
        sfile: PathBuf::from("progstate.txt"),
        detail: ProgStateDetail {
            hook: PathBuf::from("hook.sh"),
            idxd: HashMap::new(),
        },
        modified: false,
    };

    while !sigdat.got_ctrlc() {
        // disable catching of Ctrl-C
        sigdat.set_ctrlc_armed(true);
        let prompt_ptext = if pstate.modified { "*" } else { " " };
        write!(stdout, "zs-filecrawler {}>> ", prompt_ptext).unwrap();
        stdout.flush().unwrap();

        let line: String = read!("{}\n");
        let line = line.trim();

        match line {
            "exit" | "quit" => {
                if pstate.modified {
                    error!("you have modified data... call 's:clear-modified-flag' OR 's:save' before exiting");
                } else {
                    break;
                }
            }
            "s:clear-modified-flag" => {
                pstate.modified = false;
            }
            "s:load" => {
                if pstate.modified {
                    error!("you have modified data... call 's:clear-modified-flag' OR 's:save' before loading");
                } else if let Err(x) = pstate.load_from_sfile() {
                    error!("{}", x);
                }
            }
            "s:save" => {
                if let Err(x) = pstate.save_to_sfile() {
                    error!("{}", x);
                }
            }
            "i:print-debug" => {
                for (cs, ixe) in &pstate.detail.idxd {
                    println!("{} {} {:?}", hex::encode(cs), ixe.is_fin, ixe.paths);
                }
            }
            "i:clear" => {
                pstate.modified = true;
                pstate.detail.idxd.clear();
            }
            "i:gc" => {
                pstate.idx_gc();
            }
            "i:gc-aggressive" => {
                pstate.idx_gc();
                pstate.detail.idxd.retain(|_, ixe| !ixe.is_fin);
            }
            "help" => {
                println!(
                    "{}",
                    indoc!(
                        "
                    Commands:
                    exit | quit      exit this program without saving
                    s:load           load state from sfile (defaults to 'progstate.txt')
                    s:save           save state to sfile
                    s:set-file FILE  change used sfile to FILE
                    i:clear          clear the index
                    i:gc             run index garbage-collection (drop missing files
                                         and entries without associated files)
                    i:gc-aggressive  run index garbage-collection (drop already finished
                                         entries and entries without associated files)
                    i:ingest FILE    read file paths from FILE (advice: use absolute paths)
                    i:print-debug    print the whole index
                    h:set FILE       set used hook (USAGE: ./hook.sh PATH)
                    run              process files from index
                    "
                    )
                );
            }
            "run" => {
                pstate.modified = true;
                sigdat.set_ctrlc_armed(false);
                let mut n: usize = 0;
                let mut nmax = pstate.detail.idxd.len();
                for (cs, ixe) in &mut pstate.detail.idxd {
                    if sigdat.got_ctrlc() {
                        break;
                    }
                    if ixe.is_fin || ixe.paths.is_empty() {
                        nmax -= 1;
                        continue;
                    }
                    if n % 10 == 0 {
                        info!("[{}%]", (n * 100) / nmax);
                    }
                    n += 1;
                    let cshex = hex::encode(cs);
                    for path in &ixe.paths {
                        if sigdat.got_ctrlc() {
                            break;
                        }
                        println!("{} {}", cshex, path);
                        let cmdres = std::process::Command::new(&pstate.detail.hook)
                            .arg(path)
                            .status();
                        match cmdres {
                            Ok(x) if x.success() => {
                                ixe.is_fin = true;
                                break;
                            }
                            _ => {
                                warn!("HOOK failed with {:?}", cmdres);
                            }
                        }
                    }
                }
                sigdat.set_ctrlc(false);
                sigdat.set_ctrlc_armed(true);
            }
            _ => {
                let (cmd, rest) = split_command(line);
                let rest = rest.trim();
                if rest.is_empty() {
                    error!("No input file given or unknown command!");
                    continue;
                }
                match cmd {
                    "s:set-file" => {
                        pstate.sfile = PathBuf::from(rest);
                    }
                    "h:set" => {
                        pstate.detail.hook = PathBuf::from(rest);
                    }
                    "i:ingest" => {
                        let fh = read_from_file(rest);
                        if let Err(x) = &fh {
                            error!("Unable to open input file ({}: {})", rest, x);
                            continue;
                        }
                        pstate.modified = true;
                        sigdat.set_ctrlc_armed(false);
                        let mut hasher = sha2::Sha256::new();
                        for ingline in fh.unwrap().as_slice().lines() {
                            if sigdat.got_ctrlc() {
                                break;
                            }
                            if let Err(x) = &ingline {
                                warn!("Got invalid line: {}", x);
                                continue;
                            }
                            let ril = ingline.unwrap();
                            let ril = ril.trim_start();
                            if ril.is_empty() || ril.bytes().nth(0).unwrap() == b'#' {
                                continue;
                            }
                            let fh2 = read_from_file(ril);
                            if let Err(x) = &fh2 {
                                warn!("Unable to open input file ({}: {})", ril, x);
                                continue;
                            }
                            write!(stdout, ".").unwrap();
                            stdout.flush().unwrap();
                            hasher.input(fh2.unwrap().as_slice());
                            let ent = pstate.detail.idxd.entry(hasher.result_reset()).or_insert(
                                IndexEntry {
                                    is_fin: false,
                                    paths: HashSet::new(),
                                },
                            );
                            ent.paths.insert(ril.to_string());
                        }
                        println!("");
                        sigdat.set_ctrlc(false);
                        sigdat.set_ctrlc_armed(true);
                    }
                    _ => {
                        error!("Unknown command!");
                    }
                }
            }
        }
    }
}
