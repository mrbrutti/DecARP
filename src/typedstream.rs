//! Minimal reader for the classic NeXT/Apple `streamtyped` archive format
//! (the binary produced by `NSArchiver`, decoded by `NSUnarchiver`).
//!
//! This is intentionally scoped to what Apple Remote Desktop stores in its
//! `accessCredentials` blob: a dictionary of UUID strings to dictionaries of
//! `login` / `password` (`NSString`) and `sharedSecret` (`NSData`). It handles
//! the general mechanics it depends on — shared strings, class definitions,
//! object/class back-references and nested objects — so pairing is always
//! correct even though repeated strings are deduplicated in the stream.
//!
//! Format reference: https://github.com/dgelessus/python-typedstream

// Tag bytes, interpreted as signed 8-bit values.
const TAG_INTEGER_2: i8 = -127; // 0x81: next 2 bytes are the integer
const TAG_INTEGER_4: i8 = -126; // 0x82: next 4 bytes are the integer
const TAG_NEW: i8 = -124; // 0x84: a new (literal) shared string / class / object
const TAG_NIL: i8 = -123; // 0x85: nil
const TAG_END_OF_OBJECT: i8 = -122; // 0x86: end of an object's contents
const FIRST_TAG: i8 = -128;
const LAST_TAG: i8 = -111;
const FIRST_REFERENCE_NUMBER: i32 = -110; // one past the last tag

/// A decoded value from the archive.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Int/Array are produced by the general parser though ARD data doesn't read them.
pub enum Value {
    Nil,
    Int(i64),
    Str(String),
    Data(Vec<u8>),
    /// Ordered key/value pairs (dictionaries preserve insertion order here).
    Dict(Vec<(Value, Value)>),
    Array(Vec<Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Value::Data(d) => Some(d),
            _ => None,
        }
    }
}

enum ObjEntry {
    Class(Vec<u8>),
    Object(Value),
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    shared_strings: Vec<Vec<u8>>,
    objects: Vec<ObjEntry>,
}

type R<T> = Result<T, String>;

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader {
            data,
            pos: 0,
            shared_strings: Vec::new(),
            objects: Vec::new(),
        }
    }

    fn read_exact(&mut self, n: usize) -> R<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(format!(
                "unexpected end of archive at offset {} (needed {} bytes)",
                self.pos, n
            ));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_u8(&mut self) -> R<u8> {
        Ok(self.read_exact(1)?[0])
    }

    /// Read a head byte (signed) unless one was already provided (lookahead).
    fn head(&mut self, head: Option<i8>) -> R<i8> {
        match head {
            Some(h) => Ok(h),
            None => Ok(self.read_u8()? as i8),
        }
    }

    fn read_integer(&mut self, head: Option<i8>, signed: bool) -> R<i64> {
        let h = self.head(head)?;
        if !(FIRST_TAG..=LAST_TAG).contains(&h) {
            // Literal single-byte value.
            return Ok(if signed { h as i64 } else { (h as u8) as i64 });
        }
        match h {
            TAG_INTEGER_2 => {
                let b = self.read_exact(2)?;
                let v = u16::from_le_bytes([b[0], b[1]]);
                Ok(if signed { (v as i16) as i64 } else { v as i64 })
            }
            TAG_INTEGER_4 => {
                let b = self.read_exact(4)?;
                let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                Ok(if signed { (v as i32) as i64 } else { v as i64 })
            }
            _ => Err(format!("invalid integer tag {h} at offset {}", self.pos)),
        }
    }

    fn decode_ref(&self, encoded: i64) -> usize {
        (encoded as i32 - FIRST_REFERENCE_NUMBER) as usize
    }

    fn read_unshared_string(&mut self, head: Option<i8>) -> R<Option<Vec<u8>>> {
        let h = self.head(head)?;
        if h == TAG_NIL {
            return Ok(None);
        }
        let len = self.read_integer(Some(h), false)? as usize;
        Ok(Some(self.read_exact(len)?.to_vec()))
    }

    fn read_shared_string(&mut self, head: Option<i8>) -> R<Option<Vec<u8>>> {
        let h = self.head(head)?;
        if h == TAG_NIL {
            Ok(None)
        } else if h == TAG_NEW {
            let s = self
                .read_unshared_string(None)?
                .ok_or("literal shared string cannot be nil")?;
            self.shared_strings.push(s.clone());
            Ok(Some(s))
        } else {
            let enc = self.read_integer(Some(h), true)?;
            let idx = self.decode_ref(enc);
            self.shared_strings
                .get(idx)
                .cloned()
                .map(Some)
                .ok_or_else(|| format!("shared string reference {idx} out of range"))
        }
    }

    /// Read a class chain; returns the leaf (most-derived) class name.
    fn read_class(&mut self, head: Option<i8>) -> R<Vec<u8>> {
        let mut h = self.head(head)?;
        let mut leaf: Option<Vec<u8>> = None;
        while h == TAG_NEW {
            let name = self
                .read_shared_string(None)?
                .ok_or("class name cannot be nil")?;
            let _version = self.read_integer(None, true)?;
            if leaf.is_none() {
                leaf = Some(name.clone());
            }
            self.objects.push(ObjEntry::Class(name));
            h = self.head(None)?;
        }
        if h != TAG_NIL {
            // A reference: either this object's class (if no SingleClass was
            // read) or the superclass of the last one (which we ignore).
            let enc = self.read_integer(Some(h), true)?;
            let idx = self.decode_ref(enc);
            if leaf.is_none() {
                if let Some(ObjEntry::Class(n)) = self.objects.get(idx) {
                    leaf = Some(n.clone());
                }
            }
        }
        Ok(leaf.unwrap_or_default())
    }

    fn read_object(&mut self, head: Option<i8>) -> R<Value> {
        let h = self.head(head)?;
        if h == TAG_NIL {
            return Ok(Value::Nil);
        }
        if h != TAG_NEW {
            // Reference to a previously read object.
            let enc = self.read_integer(Some(h), true)?;
            let idx = self.decode_ref(enc);
            return match self.objects.get(idx) {
                Some(ObjEntry::Object(v)) => Ok(v.clone()),
                _ => Ok(Value::Nil),
            };
        }
        // New object: reserve its reference slot before reading contents so
        // any nested references number correctly.
        let slot = self.objects.len();
        self.objects.push(ObjEntry::Object(Value::Nil));

        let class = self.read_class(None)?;

        let mut vals: Vec<Value> = Vec::new();
        loop {
            let nh = self.head(None)?;
            if nh == TAG_END_OF_OBJECT {
                break;
            }
            self.read_typed_values(Some(nh), &mut vals)?;
        }

        let v = assemble(&class, vals);
        self.objects[slot] = ObjEntry::Object(v.clone());
        Ok(v)
    }

    fn read_typed_values(&mut self, head: Option<i8>, out: &mut Vec<Value>) -> R<()> {
        let enc = self
            .read_shared_string(head)?
            .ok_or("type encoding cannot be nil")?;
        for e in split_encodings(&enc) {
            self.read_value_with_encoding(&e, out)?;
        }
        Ok(())
    }

    fn read_value_with_encoding(&mut self, enc: &[u8], out: &mut Vec<Value>) -> R<()> {
        if enc.is_empty() {
            return Ok(());
        }
        match enc[0] {
            b'@' => out.push(self.read_object(None)?),
            b'#' => {
                let c = self.read_class(None)?;
                out.push(Value::Str(String::from_utf8_lossy(&c).into_owned()));
            }
            b'i' | b's' | b'l' | b'q' => out.push(Value::Int(self.read_integer(None, true)?)),
            b'I' | b'S' | b'L' | b'Q' => out.push(Value::Int(self.read_integer(None, false)?)),
            b'c' => {
                let v = self.read_u8()? as i8;
                out.push(Value::Int(v as i64));
            }
            b'C' | b'B' => {
                let v = self.read_u8()?;
                out.push(Value::Int(v as i64));
            }
            b'f' | b'd' => {
                // Not needed for ARD data; consume as integer-ish to stay aligned.
                out.push(Value::Int(self.read_integer(None, true)?));
            }
            b'+' => {
                let s = self.read_unshared_string(None)?.unwrap_or_default();
                out.push(Value::Str(String::from_utf8_lossy(&s).into_owned()));
            }
            b'*' | b'%' | b':' => {
                let s = self.read_shared_string(None)?.unwrap_or_default();
                out.push(Value::Str(String::from_utf8_lossy(&s).into_owned()));
            }
            b'[' => {
                let (len, elem) = parse_array_encoding(enc)?;
                if elem == b'c' || elem == b'C' {
                    let bytes = self.read_exact(len)?.to_vec();
                    out.push(Value::Data(bytes));
                } else {
                    let mut items = Vec::with_capacity(len);
                    for _ in 0..len {
                        self.read_value_with_encoding(&[elem], &mut items)?;
                    }
                    out.push(Value::Array(items));
                }
            }
            other => {
                return Err(format!(
                    "unsupported type encoding {:?} at offset {}",
                    other as char, self.pos
                ))
            }
        }
        Ok(())
    }

    fn read_header(&mut self) -> R<()> {
        let streamer_version = self.read_u8()?;
        if !(3..=4).contains(&streamer_version) {
            return Err(format!("unsupported streamer version {streamer_version}"));
        }
        let sig_len = self.read_u8()? as usize;
        let sig = self.read_exact(sig_len)?;
        if sig != b"streamtyped" {
            return Err(format!(
                "unexpected signature {:?} (only little-endian 'streamtyped' is supported)",
                String::from_utf8_lossy(sig)
            ));
        }
        let _system_version = self.read_integer(None, false)?;
        Ok(())
    }
}

fn assemble(class: &[u8], mut vals: Vec<Value>) -> Value {
    match class {
        b"NSString" | b"NSMutableString" => vals
            .into_iter()
            .find(|v| matches!(v, Value::Str(_)))
            .unwrap_or(Value::Str(String::new())),
        b"NSData" | b"NSMutableData" => vals
            .into_iter()
            .find(|v| matches!(v, Value::Data(_)))
            .unwrap_or(Value::Data(Vec::new())),
        b"NSDictionary" | b"NSMutableDictionary" => {
            // vals = [count, k, v, k, v, ...]
            let start = if matches!(vals.first(), Some(Value::Int(_))) {
                1
            } else {
                0
            };
            let mut pairs = Vec::new();
            let mut i = start;
            while i + 1 < vals.len() {
                let k = vals[i].clone();
                let v = vals[i + 1].clone();
                pairs.push((k, v));
                i += 2;
            }
            Value::Dict(pairs)
        }
        b"NSArray" | b"NSMutableArray" => {
            let start = if matches!(vals.first(), Some(Value::Int(_))) {
                1
            } else {
                0
            };
            Value::Array(vals.split_off(start))
        }
        _ => {
            if vals.len() == 1 {
                vals.pop().unwrap()
            } else {
                Value::Array(vals)
            }
        }
    }
}

/// Split a type-encoding string into individual top-level encodings.
/// ARD data only ever uses single encodings, but this keeps the reader honest.
fn split_encodings(enc: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < enc.len() {
        match enc[i] {
            b'[' => {
                let mut depth = 0;
                let start = i;
                while i < enc.len() {
                    match enc[i] {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                out.push(enc[start..i].to_vec());
            }
            b'{' => {
                let mut depth = 0;
                let start = i;
                while i < enc.len() {
                    match enc[i] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                out.push(enc[start..i].to_vec());
            }
            c => {
                out.push(vec![c]);
                i += 1;
            }
        }
    }
    out
}

/// Parse `[Nc]` -> (N, b'c').
fn parse_array_encoding(enc: &[u8]) -> R<(usize, u8)> {
    // enc like b"[16c]"
    if enc.len() < 3 || enc[0] != b'[' || enc[enc.len() - 1] != b']' {
        return Err(format!(
            "bad array encoding {:?}",
            String::from_utf8_lossy(enc)
        ));
    }
    let inner = &enc[1..enc.len() - 1];
    let split = inner
        .iter()
        .position(|b| !b.is_ascii_digit())
        .ok_or("array encoding missing element type")?;
    let count: usize = std::str::from_utf8(&inner[..split])
        .unwrap()
        .parse()
        .map_err(|_| "bad array length")?;
    let elem = inner[split];
    Ok((count, elem))
}

/// Decode a `streamtyped` archive into a [`Value`].
pub fn unarchive(data: &[u8]) -> Result<Value, String> {
    let mut r = Reader::new(data);
    r.read_header()?;
    let mut root = Vec::new();
    r.read_typed_values(None, &mut root)?;
    root.into_iter()
        .next()
        .ok_or_else(|| "empty archive".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_encoding_parses() {
        assert_eq!(parse_array_encoding(b"[16c]").unwrap(), (16, b'c'));
        assert_eq!(parse_array_encoding(b"[4C]").unwrap(), (4, b'C'));
        assert!(parse_array_encoding(b"garbage").is_err());
    }

    #[test]
    fn split_single_and_compound() {
        assert_eq!(split_encodings(b"@"), vec![b"@".to_vec()]);
        assert_eq!(split_encodings(b"i+"), vec![b"i".to_vec(), b"+".to_vec()]);
        assert_eq!(split_encodings(b"[16c]"), vec![b"[16c]".to_vec()]);
    }

    #[test]
    fn header_must_be_streamtyped() {
        // A big-endian "typedstream" signature is rejected (we only do LE).
        let mut bad = vec![4u8, 11];
        bad.extend_from_slice(b"typedstream");
        assert!(unarchive(&bad).is_err());
    }
}
