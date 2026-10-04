//! A serde serializer that emits nothing and only counts the bytes bincode 1.3
//! (default config: fixint, little endian, u64 lengths) would write.
//!
//! It reports, without any access to the serialized types' private fields:
//! - the byte range of selected top-level struct fields, which
//!   [`crate::precompute`] uses to splice dead buffers out of a bincode
//!   stream;
//! - the byte count per struct-field path (`pk.S.A.data`, ...), which the
//!   `precompute_bench` example prints as a size breakdown.

use std::{collections::BTreeMap, fmt::Display};

use serde::{Serialize, ser};

#[derive(Default)]
pub struct BincodeProfiler {
    /// Bytes emitted so far, i.e. the current offset in the bincode stream.
    pub pos: u64,
    /// Bytes per field path, for paths of at most `max_depth` fields.
    pub sizes: BTreeMap<String, u64>,
    /// `(start, end)` offsets of every top-level field named in `track`, in
    /// stream order.
    pub ranges: Vec<(u64, u64)>,
    max_depth: usize,
    track: &'static [&'static str],
    path: Vec<&'static str>,
}

impl BincodeProfiler {
    /// Records the per-path byte counts down to `max_depth` fields.
    pub fn sizes(max_depth: usize) -> Self {
        Self {
            max_depth,
            ..Default::default()
        }
    }

    /// Records the byte ranges of the given top-level fields.
    pub fn ranges(track: &'static [&'static str]) -> Self {
        Self {
            track,
            ..Default::default()
        }
    }

    fn add(&mut self, n: u64) {
        self.pos += n;
        for depth in 1..=self.path.len().min(self.max_depth) {
            *self.sizes.entry(self.path[..depth].join(".")).or_default() += n;
        }
    }

    fn field<T: ?Sized + Serialize>(&mut self, key: &'static str, v: &T) -> R {
        let tracked = self.path.is_empty() && self.track.contains(&key);
        let start = self.pos;
        self.path.push(key);
        let r = v.serialize(&mut *self);
        self.path.pop();
        if tracked {
            self.ranges.push((start, self.pos));
        }
        r
    }
}

#[derive(Debug)]
pub struct Error(String);

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error(msg.to_string())
    }
}

type R = Result<(), Error>;

#[rustfmt::skip]
impl ser::Serializer for &mut BincodeProfiler {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    // Must match bincode: field elements serialize as hex strings otherwise.
    fn is_human_readable(&self) -> bool { false }
    fn serialize_bool(self, _: bool) -> R { self.add(1); Ok(()) }
    fn serialize_i8(self, _: i8) -> R { self.add(1); Ok(()) }
    fn serialize_i16(self, _: i16) -> R { self.add(2); Ok(()) }
    fn serialize_i32(self, _: i32) -> R { self.add(4); Ok(()) }
    fn serialize_i64(self, _: i64) -> R { self.add(8); Ok(()) }
    fn serialize_i128(self, _: i128) -> R { self.add(16); Ok(()) }
    fn serialize_u8(self, _: u8) -> R { self.add(1); Ok(()) }
    fn serialize_u16(self, _: u16) -> R { self.add(2); Ok(()) }
    fn serialize_u32(self, _: u32) -> R { self.add(4); Ok(()) }
    fn serialize_u64(self, _: u64) -> R { self.add(8); Ok(()) }
    fn serialize_u128(self, _: u128) -> R { self.add(16); Ok(()) }
    fn serialize_f32(self, _: f32) -> R { self.add(4); Ok(()) }
    fn serialize_f64(self, _: f64) -> R { self.add(8); Ok(()) }
    fn serialize_char(self, c: char) -> R { self.add(c.len_utf8() as u64); Ok(()) }
    fn serialize_str(self, s: &str) -> R { self.add(8 + s.len() as u64); Ok(()) }
    fn serialize_bytes(self, b: &[u8]) -> R { self.add(8 + b.len() as u64); Ok(()) }
    fn serialize_none(self) -> R { self.add(1); Ok(()) }
    fn serialize_some<T: ?Sized + Serialize>(self, v: &T) -> R { self.add(1); v.serialize(self) }
    fn serialize_unit(self) -> R { Ok(()) }
    fn serialize_unit_struct(self, _: &'static str) -> R { Ok(()) }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> R { self.add(4); Ok(()) }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, v: &T) -> R { v.serialize(self) }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(self, _: &'static str, _: u32, _: &'static str, v: &T) -> R {
        self.add(4);
        v.serialize(self)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self, Error> { self.add(8); Ok(self) }
    fn serialize_tuple(self, _: usize) -> Result<Self, Error> { Ok(self) }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, Error> { Ok(self) }
    fn serialize_tuple_variant(self, _: &'static str, _: u32, _: &'static str, _: usize) -> Result<Self, Error> {
        self.add(4);
        Ok(self)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self, Error> { self.add(8); Ok(self) }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self, Error> { Ok(self) }
    fn serialize_struct_variant(self, _: &'static str, _: u32, _: &'static str, _: usize) -> Result<Self, Error> {
        self.add(4);
        Ok(self)
    }
}

macro_rules! element_impls {
    ($($trait:ident :: $method:ident),*) => {$(
        impl ser::$trait for &mut BincodeProfiler {
            type Ok = ();
            type Error = Error;
            fn $method<T: ?Sized + Serialize>(&mut self, v: &T) -> R { v.serialize(&mut **self) }
            fn end(self) -> R { Ok(()) }
        }
    )*};
}

element_impls!(
    SerializeSeq::serialize_element,
    SerializeTuple::serialize_element,
    SerializeTupleStruct::serialize_field,
    SerializeTupleVariant::serialize_field
);

impl ser::SerializeMap for &mut BincodeProfiler {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, k: &T) -> R {
        k.serialize(&mut **self)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, v: &T) -> R {
        v.serialize(&mut **self)
    }
    fn end(self) -> R {
        Ok(())
    }
}

impl ser::SerializeStruct for &mut BincodeProfiler {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, k: &'static str, v: &T) -> R {
        self.field(k, v)
    }
    fn end(self) -> R {
        Ok(())
    }
}

impl ser::SerializeStructVariant for &mut BincodeProfiler {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, k: &'static str, v: &T) -> R {
        self.field(k, v)
    }
    fn end(self) -> R {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::BincodeProfiler;

    #[derive(Serialize)]
    struct Inner {
        a: Vec<u64>,
        b: Option<(u8, String)>,
    }

    #[derive(Serialize)]
    struct Outer {
        x: u32,
        inner: Inner,
        scratch: Vec<[u8; 3]>,
        y: bool,
    }

    #[test]
    fn matches_bincode_and_finds_ranges() {
        let v = Outer {
            x: 7,
            inner: Inner {
                a: vec![1, 2, 3],
                b: Some((4, "hello".into())),
            },
            scratch: vec![[9; 3]; 5],
            y: true,
        };
        let bytes = bincode::serialize(&v).unwrap();

        let mut p = BincodeProfiler::ranges(&["scratch"]);
        v.serialize(&mut p).unwrap();
        assert_eq!(p.pos as usize, bytes.len());
        assert_eq!(p.ranges.len(), 1);
        let (start, end) = p.ranges[0];
        assert_eq!(&bytes[start as usize..][..8], &5u64.to_le_bytes());
        assert_eq!(end - start, 8 + 5 * 3);

        let mut p = BincodeProfiler::sizes(2);
        v.serialize(&mut p).unwrap();
        assert_eq!(p.sizes["inner.a"], 8 + 3 * 8);
        assert_eq!(p.sizes["inner"], 8 + 3 * 8 + 1 + 1 + 8 + 5);
    }
}
