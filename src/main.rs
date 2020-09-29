mod misc;
mod run;
mod signals;

use crate::{misc::*, signals::*};
use indoc::indoc;
use log::error;
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use text_io::read;

fn main() {
    {
        use simplelog::*;
        CombinedLogger::init(vec![TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
        )])
        .unwrap();
    }

    let sigdat = Arc::new(SignalDataIntern::new());
    register_signal_handlers(sigdat.clone());

    let mut dbpath = PathBuf::from("zsfc-progstate");

    if let Some(dbf) = std::env::args().nth(1) {
        if dbf == "--help" {
            println!("USAGE: zs-filecrawler [DB_PATH]");
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

    loop {
        // disable catching of Ctrl-C
        sigdat.set_ctrlc_armed(true);
        print!("zs-filecrawler >> ");
        std::io::stdout().flush().unwrap();

        let line: String = read!("{}\n");
        let line = line.trim();

        match line {
            "exit" | "quit" => {
                handle_dbres(dbt.flush());
                break;
            }
            "help" => {
                println!(
                    "{}",
                    indoc!(
                        "
                        Commands:
                        exit | quit       exit this program
                        clear             clear the hash² db table
                        dprint            print the hash² db table
                        flush             sync db data to disk

                        suppress-logmsgs y|n
                                          enable/disable printing log messages to stdout/stderr
                        set-logfile [FILE]
                                          set logfile (or unset it)

                        set-max-filesize SIZ|none
                                          skip any file with a length greater than SIZ
                        use-mp y|n        enable/disable parallel hook runs
                        set-hook FILE     set used hook (USAGE: ./hook.sh PATH)

                        run FILE          process files from index, read file paths from FILE
                                          (advice: use absolute paths)
                                          This processing is interruptable with Ctrl+C.
                        run-glob BASE GLOB...
                                          process files, gather file paths via GLOB pattern

                        If you want to set the database path, you must specify it
                            as the first command line argument to zs-filecrawler.
                        "
                    )
                );
            }
            "clear" => {
                for x in dbt.tree_names() {
                    if x.starts_with(dbtrees::HASHES_) {
                        handle_dbres(dbt.drop_tree(&x));
                    }
                }
            }
            "dprint" => {
                handle_dbres(foreach_hashes_tree(&dbt, |tname, t| {
                    println!("via {}:", hex::encode(tname));
                    for x in t.iter() {
                        if let Some((k, _)) = handle_dbres(x) {
                            println!("\t{}", hex::encode(&*k));
                        }
                    }
                    Ok(())
                }));
            }
            "flush" => {
                handle_dbres(dbt.flush());
            }
            "set-logfile" => {
                handle_dbres(dbt.remove(dbkeys::LOGFILE));
            }
            "set-max-filesize" => {
                handle_dbres(dbt.remove(dbkeys::MAX_FSIZ));
            }
            _ => {
                let (cmd, rest) = match line.find(char::is_whitespace) {
                    Some(pos) => (&line[..pos], line[pos + 1..].trim()),
                    None => (line, ""),
                };
                if rest.is_empty() {
                    error!("No input file given or unknown command!");
                    continue;
                }
                match cmd {
                    "use-mp" => handle_yn(&dbt, dbkeys::USE_MP, rest),
                    "suppress-logmsgs" => handle_yn(&dbt, dbkeys::SUPPRESS_LOGMSGS, rest),
                    "set-hook" => {
                        handle_dbres(dbt.insert(dbkeys::HOOK, rest));
                    }
                    "set-logfile" => {
                        handle_dbres(dbt.insert(dbkeys::LOGFILE, rest));
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
                        handle_dbres(crate::run::run(
                            &dbt,
                            &sigdat,
                            crate::run::IngestList::IndexFile(Path::new(rest)),
                        ));
                    }
                    "run-glob" => {
                        handle_dbres(crate::run::run(
                            &dbt,
                            &sigdat,
                            crate::run::IngestList::GlobPattern(rest),
                        ));
                    }
                    _ => {
                        error!("Unknown command!");
                    }
                }
            }
        }
    }
}
