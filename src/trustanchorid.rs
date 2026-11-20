/// A trust anchor identifier (draft-ietf-tls-trust-anchor-ids): a sequence
/// of base-128 OID components, encoded the same way as in the Go reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchorId(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
pub struct TrustAnchorIdError(pub String);

impl std::fmt::Display for TrustAnchorIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for TrustAnchorIdError {}

fn append_base128(dst: &mut Vec<u8>, v: u64) {
    let mut l = if v == 0 {
        1
    } else {
        let mut n = v;
        let mut c = 0;
        while n != 0 {
            c += 1;
            n >>= 7;
        }
        c
    };
    while l > 0 {
        let b = ((v >> (7 * (l - 1))) & 0x7f) as u8;
        dst.push(if l > 1 { b | 0x80 } else { b });
        l -= 1;
    }
}

fn parse_base128(input: &[u8]) -> Option<(u64, &[u8])> {
    if input.is_empty() {
        return None;
    }
    if input[0] == 0x80 {
        return None; // not minimally encoded
    }
    let mut ret: u64 = 0;
    let mut rest = input;
    loop {
        if rest.is_empty() || (ret << 7) >> 7 != ret {
            return None;
        }
        let b = rest[0];
        ret = (ret << 7) | (b & 0x7f) as u64;
        rest = &rest[1..];
        if b & 0x80 == 0 {
            return Some((ret, rest));
        }
    }
}

impl TrustAnchorId {
    /// Parses a dotted-decimal string like "32473.1".
    pub fn parse(s: &str) -> Result<Self, TrustAnchorIdError> {
        let mut t = Vec::new();
        for part in s.split('.') {
            let v: u64 = part.parse().map_err(|_| {
                TrustAnchorIdError(format!("invalid trust anchor ID component {part:?}"))
            })?;
            append_base128(&mut t, v);
        }
        if t.is_empty() {
            return Err(TrustAnchorIdError("empty trust anchor ID".into()));
        }
        Ok(TrustAnchorId(t))
    }

    pub fn from_bytes(b: Vec<u8>) -> Self {
        TrustAnchorId(b)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The dotted-decimal string representation.
    pub fn to_dotted_string(&self) -> Result<String, TrustAnchorIdError> {
        if self.0.is_empty() {
            return Err(TrustAnchorIdError("invalid (empty) trust anchor ID".into()));
        }
        let mut s = String::new();
        let mut rest: &[u8] = &self.0;
        while !rest.is_empty() {
            let (v, r) = parse_base128(rest).ok_or_else(|| {
                TrustAnchorIdError(format!("invalid trust anchor ID: {:x?}", self.0))
            })?;
            if !s.is_empty() {
                s.push('.');
            }
            s.push_str(&v.to_string());
            rest = r;
        }
        Ok(s)
    }

    /// The `cosigner_name`/`log_origin` format used in CosignedSubtree
    /// (§5.3.1): `"oid/1.3.6.1.4.1." + dotted-decimal representation`.
    pub fn oid_name(&self) -> Result<String, TrustAnchorIdError> {
        if self.0.is_empty() {
            return Err(TrustAnchorIdError("empty trust anchor ID".into()));
        }
        let mut rest: &[u8] = &self.0;
        while !rest.is_empty() {
            match parse_base128(rest) {
                Some((_, r)) => rest = r,
                None => {
                    return Err(TrustAnchorIdError(format!(
                        "trust anchor ID {:x?} has an invalid or out-of-range OID component",
                        self.0
                    )))
                }
            }
        }
        Ok(format!("oid/1.3.6.1.4.1.{}", self.to_dotted_string()?))
    }

    /// Log ID = {caID logs(0) N} where N is the log number (§5.2).
    pub fn log_id(&self, log_number: u16) -> TrustAnchorId {
        let mut id = self.0.clone();
        append_base128(&mut id, 0);
        append_base128(&mut id, log_number as u64);
        TrustAnchorId(id)
    }

    /// Landmark ID = {caID landmarks(1) N L} (§5.1).
    pub fn landmark_id(&self, log_number: u16, landmark_num: u32) -> TrustAnchorId {
        let mut id = self.0.clone();
        append_base128(&mut id, 1);
        append_base128(&mut id, log_number as u64);
        append_base128(&mut id, landmark_num as u64);
        TrustAnchorId(id)
    }
}
