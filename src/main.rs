#[macro_use]
extern crate log;

use digest::Digest;
use generic_array::{typenum::U32, GenericArray};
use hashbrown::{HashMap, HashSet};
use indoc::indoc;
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use text_io::{read, try_read, try_scan};

mod signals;
use signals::*;

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

fn split_command(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(pos) => (&line[..pos], &line[pos + 1..]),
        None => (line, ""),
    }
}

fn read_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<readfilez::FileHandle> {
    readfilez::read_from_file(std::fs::File::open(path))
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
struct IndexEntry {
    is_fin: bool,
    paths: HashSet<String>,
}

type Index = HashMap<GenericArray<u8, U32>, IndexEntry>;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
struct ProgStateDetail {
    hook: PathBuf,
    idxd: Index,
    idx_max_filesize: Option<u64>,
    use_multiproc: bool,
}

#[derive(Clone, Debug)]
struct ProgState {
    inpf_prefix: PathBuf,
    sfile: PathBuf,
    detail: ProgStateDetail,
    modified: bool,
}

impl ProgStateDetail {
    fn run(&mut self, sigdat: SignalData) {
        use rayon::prelude::*;
        sigdat.set_ctrlc_armed(false);
        let n = AtomicUsize::new(0);
        let nmax = AtomicUsize::new(self.idxd.len());
        let hook = &self.hook;
        let nunit: usize = std::cmp::max(10, self.idxd.len() / 1000);

        let worker = |cs, ixe: &mut IndexEntry| {
            if ixe.is_fin || ixe.paths.is_empty() {
                nmax.fetch_sub(1, Ordering::SeqCst);
                return;
            }
            let n_ = n.load(Ordering::SeqCst);
            if n_ % nunit == 0 {
                info!("[{}%]", (n_ * 100) / nmax.load(Ordering::SeqCst));
            }
            n.fetch_add(1, Ordering::SeqCst);
            let cshex = hex::encode(cs);
            for path in &ixe.paths {
                if sigdat.got_ctrlc() {
                    break;
                }
                println!("{} {}", cshex, path);
                let cmdres = std::process::Command::new(hook).arg(path).status();
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
        };

        if self.use_multiproc {
            self.idxd.par_iter_mut().for_each(|(cs, ixe)| {
                if sigdat.got_ctrlc() {
                    return;
                }
                worker(cs, ixe);
            });
        } else {
            for (cs, ixe) in &mut self.idxd {
                if sigdat.got_ctrlc() {
                    break;
                }
                worker(cs, ixe);
            }
        }
        sigdat.set_ctrlc_armed(true);
    }
}


fn idx_ingest(idxd: &mut Index, sigdat: SignalData, filename: &Path, idx_max_filesize: Option<u64>) -> bool {
    fn does_exceed_max_filesize(filename: &Path, idx_max_filesize: Option<u64>) -> bool {
        if let Some(max_fsiz) = &idx_max_filesize {
            if let Ok(fmd) = std::fs::metadata(filename) {
                if fmd.len() > *max_fsiz {
                    return true;
                }
            }
        }
        return false;
    }

    if does_exceed_max_filesize(filename, idx_max_filesize) {
        error!("File is too big: {}", filename.display());
        return false;
    }
    let fh = read_from_file(filename);
    if let Err(x) = &fh {
        error!("Unable to open input file ({}: {})", filename.display(), x);
        return false;
    }
    sigdat.set_ctrlc_armed(false);
    let mut stdout = std::io::stdout();
    let mut hasher = sha2::Sha256::new();
    let mut cnt_plus: usize = 0;
    let mut cnt_dup: usize = 0;
    let mut cnt_fin: usize = 0;
    for ingline in fh.unwrap().as_slice().lines() {
        if sigdat.got_ctrlc() {
            break;
        }
        if let Err(x) = &ingline {
            writeln!(stdout, "").unwrap();
            warn!("Got invalid line: {}", x);
            continue;
        }
        let ril = ingline.unwrap();
        let ril = ril.trim_start();
        if ril.is_empty() || ril.bytes().nth(0).unwrap() == b'#' {
            continue;
        }
        if does_exceed_max_filesize(Path::new(ril), idx_max_filesize) {
            error!("File is too big: {}", ril);
            continue;
        }
        let fh2 = read_from_file(ril);
        if let Err(x) = &fh2 {
            writeln!(stdout, "").unwrap();
            warn!("Unable to open input file ({}: {})", ril, x);
            continue;
        }
        stdout.flush().unwrap();
        hasher.input(fh2.unwrap().as_slice());
        let ent = idxd.entry(hasher.result_reset()).or_insert(IndexEntry {
            is_fin: false,
            paths: HashSet::new(),
        });
        if ent.is_fin {
            cnt_fin += 1;
        } else {
            cnt_plus += 1;
            if !ent.paths.is_empty() {
                cnt_dup += 1;
            }
            ent.paths.insert(ril.to_string());
        }
        write!(stdout, "\r{} inserted with {} DUP / {} skipped", cnt_plus, cnt_dup, cnt_fin).unwrap();
    }
    writeln!(stdout, "").unwrap();
    sigdat.set_ctrlc_armed(true);
    return true;
}

impl ProgState {
    // resolve $x accoording to self.inpf_prefix
    fn resolve_path(&self, x: &str) -> PathBuf {
        if Path::new(x).is_relative() {
            self.inpf_prefix.join(x)
        } else {
            PathBuf::from(x)
        }
    }

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

    // fnx(ixe) -> bool :: @return : keep if true
    fn idx_gc<FnT: Fn(&IndexEntry) -> bool>(&mut self, fnx: FnT) {
        use rayon::prelude::*;

        self.modified = true;
        self.detail.idxd.par_iter_mut().for_each(|(_, ixe)| {
            if ixe.is_fin {
                ixe.paths.clear();
            } else {
                ixe.paths.retain(|f| Path::new(f).is_file());
            }
            ixe.paths.shrink_to_fit();
        });
        self.detail.idxd.retain(|_, ixe| fnx(ixe));
    }
}

fn main() {
    logger_init();

    let sigdat = Arc::new(SignalDataIntern::new());
    register_signal_handlers(sigdat.clone());

    let mut stdout = std::io::stdout();

    let mut pstate = ProgState {
        inpf_prefix: PathBuf::from("."),
        sfile: PathBuf::from("progstate.txt"),
        detail: ProgStateDetail {
            hook: PathBuf::from("hook.sh"),
            idxd: HashMap::new(),
            idx_max_filesize: None,
            use_multiproc: false,
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
            "i:clear-unfin" => {
                pstate.idx_gc(|ixe| ixe.is_fin);
            }
            "i:gc" => {
                pstate.idx_gc(|ixe| !ixe.paths.is_empty() || ixe.is_fin);
            }
            "i:gc-aggressive" => {
                pstate.idx_gc(|ixe| !ixe.paths.is_empty() && !ixe.is_fin);
            }
            "help" => {
                println!(
                    "{}",
                    indoc!(
                        "
                    Commands:
                    exit | quit      exit this program without saving
                    set-inpf-prefix D use a different directory than the current to
                                         resolve paths @:
                                         - s:set-file
                                         - h:set
                                         - i:ingest (only the argument to ingest,
                                             not the content of the ingest file)
                    i:set-max-filesize SIZ|none
                                     skip any file with a length greater than SIZ
                    s:load           load state from sfile (defaults to 'progstate.txt')
                    s:save           save state to sfile
                    s:set-file FILE  change used sfile to FILE
                    s:use-mp y|n     enable/disable parallel hook runs
                    i:clear          clear the index
                    i:clear-unfin    clear all unfinished index entries
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
                pstate.detail.run(sigdat.clone());
            }
            _ => {
                let (cmd, rest) = split_command(line);
                let rest = rest.trim();
                if rest.is_empty() {
                    error!("No input file given or unknown command!");
                    continue;
                }
                match cmd {
                    "set-inpf-prefix" => {
                        pstate.inpf_prefix = PathBuf::from(rest);
                    }
                    "s:set-file" => {
                        pstate.sfile = pstate.resolve_path(rest);
                    }
                    "h:set" => {
                        pstate.detail.hook = pstate.resolve_path(rest);
                    }
                    "i:set-max-filesize" => {
                        if rest == "none" {
                            pstate.detail.idx_max_filesize = None;
                            continue;
                        }
                        let bytes_cnt = match byte_unit::Byte::from_str(rest) {
                            Err(x) => {
                                error!("Got invalid byte unit value: {}: {:?}", rest, x);
                                continue;
                            }
                            Ok(x) => x.get_bytes(),
                        };
                        if bytes_cnt >= (std::isize::MAX as u128) {
                            error!("Given byte unit value is too big: {}", rest);
                            continue;
                        }
                        pstate.detail.idx_max_filesize = Some(bytes_cnt as u64);
                    }
                    "i:ingest" => {
                        let ingest_inf = pstate.resolve_path(rest);
                        if idx_ingest(&mut pstate.detail.idxd, sigdat.clone(), &ingest_inf, pstate.detail.idx_max_filesize) {
                            pstate.modified = true;
                        }
                    }
                    "s:use-mp" => match rest {
                        "Y" | "y" | "yes" => pstate.detail.use_multiproc = true,
                        "N" | "n" | "no" => pstate.detail.use_multiproc = false,
                        _ => error!("unknown specifier"),
                    },
                    _ => {
                        error!("Unknown command!");
                    }
                }
            }
        }
    }
}
