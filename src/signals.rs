use log::warn;
use signal_hook::consts::SIGINT;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub struct SignalDataIntern {
    ctrlc: AtomicBool,
    ctrlc_armed: AtomicBool,
}
pub type SignalData = Arc<SignalDataIntern>;

#[must_use]
pub struct SignalDataUnArmed<'parent> {
    parent: &'parent SignalDataIntern,
}

impl SignalDataIntern {
    pub const fn new() -> Self {
        Self {
            ctrlc: AtomicBool::new(false),
            ctrlc_armed: AtomicBool::new(true),
        }
    }
    pub fn handle_ctrlc(&self) {
        if self.is_ctrlc_armed() {
            std::process::exit(128 + SIGINT);
        } else {
            self.ctrlc.store(true, Ordering::SeqCst);
        }
    }
    pub fn is_ctrlc_armed(&self) -> bool {
        self.ctrlc_armed.load(Ordering::SeqCst)
    }
    pub fn set_ctrlc_armed(&self, val: bool) {
        self.ctrlc_armed.store(val, Ordering::SeqCst);
        self.ctrlc.store(false, Ordering::SeqCst);
    }
    pub fn disarm_aquire(&self) -> SignalDataUnArmed<'_> {
        self.set_ctrlc_armed(false);
        SignalDataUnArmed { parent: self }
    }
}

impl SignalDataUnArmed<'_> {
    pub fn got_ctrlc(&self) -> bool {
        self.parent.ctrlc.load(Ordering::SeqCst)
    }
}

impl Drop for SignalDataUnArmed<'_> {
    fn drop(&mut self) {
        self.parent.set_ctrlc_armed(true);
    }
}

pub fn register_signal_handlers(dat: SignalData) {
    unsafe { signal_hook::low_level::register(SIGINT, move || dat.handle_ctrlc()) }
        .map_err(|e| {
            warn!("Failed to register for SIGINT {:?}", e);
            e
        })
        .ok();
}
