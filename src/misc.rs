use log::error;
use std::{borrow::Cow, path::Path};

pub mod dbkeys {
    pub const HOOK: &[u8] = b"hook";
    pub const LOGFILE: &[u8] = b"logfile";
    pub const MAX_FSIZ: &[u8] = b"max-filesize";
    pub const SUPPRESS_LOGMSGS: &[u8] = b"suppress-logmsgs";
    pub const USE_MP: &[u8] = b"use-mp";
}

pub mod dbtrees {
    pub const HASHES_: &[u8] = b"hashes:";
}

#[inline]
pub fn read_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<readfilez::FileHandle> {
    readfilez::read_from_file(std::fs::File::open(path))
}

pub fn handle_dbres<T>(x: Result<T, sled::Error>) -> Option<T> {
    x.map_err(|e| {
        error!("{}", e);
    })
    .ok()
}

pub fn handle_yn(t: &sled::Tree, key: &[u8], rest: &str) {
    handle_dbres(match rest {
        "Y" | "YES" | "Yes" | "y" | "yes" => t.insert(key, &[]),
        "N" | "NO" | "No" | "n" | "no" => t.remove(key),
        _ => {
            error!("unknown specifier");
            return;
        }
    });
}

pub fn foreach_hashes_tree<F>(dbt: &sled::Db, mut f: F) -> Result<(), sled::Error>
where
    F: FnMut(&[u8], sled::Tree) -> Result<(), sled::Error>,
{
    for x in dbt.tree_names() {
        if x.starts_with(dbtrees::HASHES_) {
            f(&x[dbtrees::HASHES_.len()..], dbt.open_tree(&x)?)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct SyntaxError;

pub struct ShellwordSplitter<'a> {
    input: &'a str,
}

impl<'a> ShellwordSplitter<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input }
    }

    fn skip_whitespace(&mut self) {
        let mut it = self.input.char_indices();
        self.input = loop {
            break match it.next() {
                None => "",
                Some((pos, x)) if !x.is_whitespace() => &self.input[pos..],
                _ => continue,
            };
        };
    }
}

enum StrShardInner {
    Borrowed(usize),
    Owned(String),
}

impl StrShardInner {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Borrowed(ref len) => *len,
            Self::Owned(ref owned) => owned.len(),
        }
    }

    fn to_mut(&mut self, whole: &str) -> &mut String {
        match *self {
            Self::Borrowed(slen) => {
                *self = Self::Owned(whole[..slen].to_string());
                match *self {
                    Self::Borrowed(_) => unreachable!(),
                    Self::Owned(ref mut x) => x,
                }
            }
            Self::Owned(ref mut x) => x,
        }
    }
}

pub struct StrShard<'a> {
    whole: &'a str,
    inner: StrShardInner,
}

impl<'a> StrShard<'a> {
    #[inline]
    pub fn new(whole: &'a str) -> Self {
        Self {
            whole,
            inner: StrShardInner::Borrowed(0),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn skip(&mut self, len: usize) {
        if !self.is_empty() {
            return;
        }
        self.whole = &self.whole[len..];
    }

    // promotes self to owned
    pub fn push_owned(&mut self, ch: char) {
        self.inner.to_mut(self.whole).push(ch);
    }

    pub fn push(&mut self, ch: char) {
        use StrShardInner as I;
        match &mut self.inner {
            I::Borrowed(slen) => {
                let slen = *slen;
                let new_len = slen + ch.len_utf8();
                self.inner = if self.whole[slen..].chars().next() != Some(ch) {
                    // promote to owned
                    let mut owned = self.whole[..slen].to_string();
                    owned.push(ch);
                    I::Owned(owned)
                } else {
                    // remain borrowed
                    I::Borrowed(new_len)
                };
            }
            I::Owned(ref mut x) => {
                x.push(ch);
            }
        };
    }

    pub fn finish(self) -> Option<Cow<'a, str>> {
        let Self { whole, inner } = self;
        use StrShardInner as I;
        if inner.len() == 0 {
            None
        } else {
            Some(match inner {
                I::Borrowed(slen) => Cow::Borrowed(&whole[..slen]),
                I::Owned(x) => Cow::Owned(x),
            })
        }
    }
}

#[inline]
fn ch_is_quote(ch: char) -> bool {
    match ch {
        '"' | '\'' => true,
        _ => false,
    }
}

impl<'a> Iterator for ShellwordSplitter<'a> {
    type Item = Result<Cow<'a, str>, SyntaxError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.skip_whitespace();
        let mut it = self.input.char_indices();
        let mut quotec = None;
        let mut ret = StrShard::<'a>::new(self.input);
        while let Some((cpos, cx)) = it.next() {
            match cx {
                '\\' => {
                    // escape works the same, no matter if inside or outside of quotes
                    ret.push_owned(match it.next().map(|i| i.1) {
                        Some('n') => '\n',
                        Some('t') => '\t',
                        Some('r') => '\r',
                        Some(x) if quotec.is_some() && x.is_whitespace() => continue,
                        Some(x) => x,
                        None => return Some(Err(SyntaxError)),
                    });
                }
                _ if Some(cx) == quotec => {
                    // end of quotation
                    quotec = None;
                    match it.next() {
                        Some((npos, nx)) if nx.is_whitespace() => {
                            // simple case: the ending quote is followed by an separator
                            // we can thus skip the whitespace and return our item
                            self.input = &self.input[npos..];
                            return ret.finish().map(Ok);
                        }
                        Some((_, nx)) if ch_is_quote(nx) => {
                            // medium case: the ending quote if directly followed by another quote
                            // thus, remain in quote mode
                            quotec = Some(nx);
                        }
                        Some((_, nx)) => {
                            // complex case: the ending quote is followed by more data which
                            // belongs to the same argument
                            ret.push_owned(nx);
                        }
                        None => {
                            // simple case: the ending quote is followed by EOF
                            self.input = "";
                            return ret.finish().map(Ok);
                        }
                    }
                }
                _ if quotec.is_none() && ch_is_quote(cx) => {
                    // start of quotation
                    quotec = Some(cx);
                    // allow the algo to reuse simple, quoted args
                    ret.skip(1);
                }
                _ if quotec.is_none() && cx.is_whitespace() => {
                    // argument separator, this will never happen on the first iteration
                    self.input = &self.input[cpos..];
                    return ret.finish().map(Ok);
                }
                _ => ret.push(cx),
            }
        }
        if quotec.is_some() {
            return Some(Err(SyntaxError));
        }
        self.input = "";
        ret.finish().map(Ok)
    }
}

#[cfg(test)]
mod tests {
    /// split_shellwords tests were taken from
    /// https://docs.rs/shellwords/1.1.0/src/shellwords/lib.rs.html
    /// License: MIT
    fn split(x: &str) -> Result<Vec<String>, super::SyntaxError> {
        super::ShellwordSplitter::new(x)
            .map(|i| i.map(std::borrow::Cow::into_owned))
            .collect()
    }

    #[test]
    fn nothing_special() {
        assert_eq!(split("a b c d").unwrap(), ["a", "b", "c", "d"]);
    }

    #[test]
    fn quoted_strings() {
        assert_eq!(split("a \"b b\" a").unwrap(), ["a", "b b", "a"]);
    }

    #[test]
    fn escaped_double_quotes() {
        assert_eq!(split("a \"\\\"b\\\" c\" d").unwrap(), ["a", "\"b\" c", "d"]);
    }

    #[test]
    fn escaped_single_quotes() {
        assert_eq!(split("a \"'b' c\" d").unwrap(), ["a", "'b' c", "d"]);
    }

    #[test]
    fn escaped_spaces() {
        assert_eq!(split("a b\\ c d").unwrap(), ["a", "b c", "d"]);
    }

    #[test]
    fn bad_double_quotes() {
        split("a \"b c d e").unwrap_err();
    }

    #[test]
    fn bad_single_quotes() {
        split("a 'b c d e").unwrap_err();
    }

    #[test]
    fn bad_quotes() {
        split("one '\"\"\"").unwrap_err();
    }

    #[test]
    fn trailing_whitespace() {
        assert_eq!(split("a b c d ").unwrap(), ["a", "b", "c", "d"]);
    }
}
