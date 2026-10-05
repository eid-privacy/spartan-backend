//! Would a compact per-scalar encoding beat "bincode + zstd" for
//! `target/precompute.bin`?
//!
//! Pulls every field element (a serde tuple of 32 `u8`s) out of the stored
//! `pk` and `prep`, then compares, on that real data:
//! - today's split: zstd decompress vs. bincode deserialize, per blob;
//! - canonical / raw-Montgomery 32-byte scalars behind zstd;
//! - a compact encoding: one tag byte (bit 7 = negated, bits 0..6 = length)
//!   followed by the significant little-endian bytes of `x` or `-x`, with and
//!   without zstd, single- and multi-threaded.
//!
//! ```text
//! cargo run --release --example scalar_compact_bench -- ../circuits/c0200_swiyu_jwt
//! ```

use std::{
    fmt::Display,
    path::PathBuf,
    time::{Duration, Instant},
};

use ff::{Field, PrimeField};
use halo2curves::serde::SerdeObject;
use serde::{Serialize, ser};
use spartan_backend::precompute::{self, precompute_path};
use vega_prover::traits::Engine;

type F = <spartan_backend::E as Engine>::Scalar;

const THREADS: usize = 8;

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn best<T>(runs: usize, mut f: impl FnMut() -> T) -> (Duration, T) {
    let mut best = Duration::MAX;
    let mut out = None;
    for _ in 0..runs {
        let t = Instant::now();
        let v = f();
        best = best.min(t.elapsed());
        out = Some(v);
    }
    (best, out.unwrap())
}

fn zstd1(b: &[u8]) -> Vec<u8> {
    zstd::bulk::compress(b, 1).unwrap()
}

fn unzstd(b: &[u8], len: usize) -> Vec<u8> {
    zstd::bulk::decompress(b, len).unwrap()
}

/// zstd in `THREADS` independent frames, decompressed in parallel.
fn zstd_par(b: &[u8]) -> Vec<(usize, Vec<u8>)> {
    let chunk = b.len().div_ceil(32 * THREADS) * 32;
    std::thread::scope(|s| {
        let hs: Vec<_> = b
            .chunks(chunk)
            .map(|c| s.spawn(move || (c.len(), zstd1(c))))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn unzstd_par(frames: &[(usize, Vec<u8>)]) -> Vec<Vec<u8>> {
    std::thread::scope(|s| {
        let hs: Vec<_> = frames
            .iter()
            .map(|(len, f)| s.spawn(move || unzstd(f, *len)))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .expect("usage: scalar_compact_bench <circuit_dir>"),
    );
    let runs = 3;
    let bytes = std::fs::read(precompute_path(&dir)).expect("read precompute.bin");
    let fingerprint = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
    let (pk, prep) = precompute::decode(&bytes, fingerprint).expect("decode");

    println!("== today's format, single-threaded split");
    let u64_at =
        |i: usize| u64::from_le_bytes(bytes[12 + 8 * i..][..8].try_into().unwrap()) as usize;
    let (pk_len, prep_len, pk_zlen) = (u64_at(0), u64_at(1), u64_at(2));
    let (zpk, zprep) = bytes[36..].split_at(pk_zlen);
    for (name, z, len) in [("pk", zpk, pk_len), ("prep", zprep, prep_len)] {
        let raw = unzstd(z, len);
        let (tz, _) = best(runs, || unzstd(&z, raw.len()));
        let td = if name == "pk" {
            best(runs, || {
                drop(
                    bincode::deserialize::<spartan_backend::online_prover::ProverKey>(&raw)
                        .unwrap(),
                )
            })
            .0
        } else {
            best(runs, || {
                drop(
                    bincode::deserialize::<spartan_backend::online_prover::PrepSnark>(&raw)
                        .unwrap(),
                )
            })
            .0
        };
        println!(
            "{name:>4}: {:>7.1} MiB raw -> {:>5.1} MiB zstd   unzstd {tz:>9.3?}   bincode {td:>9.3?}",
            mib(raw.len()),
            mib(z.len())
        );
    }

    let mut c = Collector::default();
    pk.serialize(&mut c).unwrap();
    prep.serialize(&mut c).unwrap();
    drop((pk, prep));
    let scalars: Vec<F> = c
        .scalars
        .iter()
        .map(|r| F::from_repr((*r).into()).unwrap())
        .collect();
    let n = scalars.len();
    println!(
        "\n== {:.2}M scalars ({:.1} MiB) + {:.1} MiB of other bincode bytes",
        n as f64 / 1e6,
        mib(32 * n),
        mib(c.other as usize)
    );

    let (tags, payload) = encode_compact(&scalars);
    let mut hist = [[0usize; 33]; 2];
    for t in &tags {
        hist[(t >> 7) as usize][(t & 63) as usize] += 1;
    }
    println!("byte length histogram (x or -x, whichever is shorter):");
    for len in 0..=32 {
        let (p, m) = (hist[0][len], hist[1][len]);
        if p + m > 0 {
            println!(
                "  {len:>2} B: {:>5.1}%  (+ {:>5.1}%, - {:>5.1}%)",
                100.0 * (p + m) as f64 / n as f64,
                100.0 * p as f64 / n as f64,
                100.0 * m as f64 / n as f64
            );
        }
    }

    println!("\n== encodings of the scalars alone (decode = bytes on disk -> Vec<F>)");
    let canon: Vec<u8> = scalars.iter().flat_map(|x| repr(x)).collect();
    let mont: Vec<u8> = scalars.iter().flat_map(|x| x.to_raw_bytes()).collect();

    let z = zstd1(&canon);
    let (t, v) = best(runs, || -> Vec<F> {
        unzstd(&z, canon.len())
            .chunks_exact(32)
            .map(|c| F::from_repr(c.into()).unwrap())
            .collect()
    });
    assert!(v == scalars);
    row("canonical 32 B + zstd, from_repr", z.len(), t);

    let z = zstd1(&mont);
    let (tz, _) = best(runs, || unzstd(&z, mont.len()));
    let (t, v) = best(runs, || -> Vec<F> {
        unzstd(&z, mont.len())
            .chunks_exact(32)
            .map(F::from_raw_bytes_unchecked)
            .collect()
    });
    assert!(v == scalars);
    row("Montgomery 32 B + zstd, unchecked", z.len(), t);
    println!("{:>48}  (of which unzstd {tz:.3?})", "");

    let zp = zstd_par(&mont);
    let (t, v) = best(runs, || -> Vec<F> {
        let parts = unzstd_par(&zp);
        let mut out = Vec::with_capacity(n);
        for p in &parts {
            out.extend(p.chunks_exact(32).map(F::from_raw_bytes_unchecked));
        }
        out
    });
    assert!(v == scalars);
    let size = zp.iter().map(|(_, f)| f.len()).sum();
    row(&format!("Montgomery + zstd, {THREADS} frames ||"), size, t);

    // Same frames, but each decompressed straight into its slice of the final
    // `Vec<F>`: no intermediate buffer.
    let (t, v) = best(runs, || -> Vec<F> {
        let mut out = vec![F::ZERO; n];
        // SAFETY: `F` is four little-endian u64 limbs, which is exactly what
        // `to_raw_bytes` wrote on this (little-endian) machine.
        let dst = unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, 32 * n) };
        std::thread::scope(|s| {
            let mut rest = dst;
            for (len, f) in &zp {
                let (chunk, tail) = rest.split_at_mut(*len);
                rest = tail;
                s.spawn(move || {
                    zstd::bulk::decompress_to_buffer(f, chunk).unwrap();
                });
            }
        });
        out
    });
    assert!(v == scalars);
    row(
        &format!("Montgomery + zstd, {THREADS} fr., in place"),
        size,
        t,
    );

    let compact = tags.len() + payload.len();
    let (t, v) = best(runs, || decode_compact(&tags, &payload));
    assert!(v == scalars);
    row("compact, no zstd", compact, t);
    println!(
        "{:>48}  (tags {:.1} MiB + payload {:.1} MiB)",
        "",
        mib(tags.len()),
        mib(payload.len())
    );

    let chunks = split_compact(&tags, THREADS);
    let (t, v) = best(runs, || {
        decode_compact_par::<true>(&tags, &payload, &chunks)
    });
    assert!(v == scalars);
    row(
        &format!("compact, no zstd, table, {THREADS} thr."),
        compact,
        t,
    );
    let (t, v) = best(runs, || {
        decode_compact_par::<false>(&tags, &payload, &chunks)
    });
    assert!(v == scalars);
    row(&format!("compact, no zstd, {THREADS} threads"), compact, t);

    let (zt, zpl) = (zstd1(&tags), zstd1(&payload));
    let (t, v) = best(runs, || {
        decode_compact(&unzstd(&zt, tags.len()), &unzstd(&zpl, payload.len()))
    });
    assert!(v == scalars);
    row("compact + zstd (tags, payload)", zt.len() + zpl.len(), t);

    let (t, v) = best(runs, || {
        let (t, p) = std::thread::scope(|s| {
            let t = s.spawn(|| unzstd(&zt, tags.len()));
            let p = unzstd(&zpl, payload.len());
            (t.join().unwrap(), p)
        });
        decode_compact_par::<false>(&t, &p, &chunks)
    });
    assert!(v == scalars);
    row(
        &format!("compact + zstd, {THREADS} threads"),
        zt.len() + zpl.len(),
        t,
    );

    let (t, v) = best(runs, || {
        decode_compact_t::<true>(&unzstd(&zt, tags.len()), &unzstd(&zpl, payload.len()))
    });
    assert!(v == scalars);
    row("compact + zstd, 1-byte table", zt.len() + zpl.len(), t);

    let (t, v) = best(runs, || {
        let (t, p) = std::thread::scope(|s| {
            let t = s.spawn(|| unzstd(&zt, tags.len()));
            let p = unzstd(&zpl, payload.len());
            (t.join().unwrap(), p)
        });
        decode_compact_par::<true>(&t, &p, &chunks)
    });
    assert!(v == scalars);
    row(
        &format!("compact + zstd, table, {THREADS} threads"),
        zt.len() + zpl.len(),
        t,
    );

    println!(
        "\n== per-scalar construction, {:.2}M scalars",
        n as f64 / 1e6
    );
    let small: Vec<u64> = scalars
        .iter()
        .map(|x| u64::from_le_bytes(repr(x)[..8].try_into().unwrap()))
        .collect();
    let (t, _) = best(runs, || -> Vec<F> {
        small.iter().map(|&v| F::from(v)).collect()
    });
    println!("F::from(u64)                     {t:>9.3?}");
    let (t, _) = best(runs, || -> Vec<F> {
        mont.chunks_exact(32)
            .map(F::from_raw_bytes_unchecked)
            .collect()
    });
    println!("from_raw_bytes_unchecked (memcpy) {t:>8.3?}");
}

/// `[sign][byte]` -> `±byte`, built once.
fn table() -> &'static [[F; 256]; 2] {
    static T: std::sync::OnceLock<[[F; 256]; 2]> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let pos: [F; 256] = std::array::from_fn(|i| F::from(i as u64));
        [pos, pos.map(|x| -x)]
    })
}

fn repr(x: &F) -> [u8; 32] {
    x.to_repr().as_ref().try_into().unwrap()
}

fn row(name: &str, size: usize, t: Duration) {
    println!("{name:<40} {:>7.1} MiB  {t:>9.3?}", mib(size));
}

/// Tag per scalar plus the significant bytes of whichever of `x`, `-x` is
/// shorter.
fn encode_compact(scalars: &[F]) -> (Vec<u8>, Vec<u8>) {
    let len = |r: &[u8; 32]| 32 - r.iter().rev().take_while(|&&b| b == 0).count();
    let mut tags = Vec::with_capacity(scalars.len());
    let mut payload = Vec::new();
    for x in scalars {
        let (p, m) = (repr(x), repr(&-*x));
        let (lp, lm) = (len(&p), len(&m));
        if lm < lp {
            tags.push(0x80 | lm as u8);
            payload.extend_from_slice(&m[..lm]);
        } else {
            tags.push(lp as u8);
            payload.extend_from_slice(&p[..lp]);
        }
    }
    (tags, payload)
}

fn decode_compact(tags: &[u8], payload: &[u8]) -> Vec<F> {
    decode_compact_t::<false>(tags, payload)
}

fn decode_compact_t<const TABLE: bool>(tags: &[u8], payload: &[u8]) -> Vec<F> {
    let mut out = Vec::with_capacity(tags.len());
    decode_compact_into::<TABLE>(tags, payload, &mut out);
    out
}

fn decode_compact_into<const TABLE: bool>(tags: &[u8], payload: &[u8], out: &mut Vec<F>) {
    let mut at = 0;
    for &t in tags {
        let n = (t & 63) as usize;
        let b = &payload[at..at + n];
        at += n;
        let x = match n {
            0 => F::ZERO,
            1 if TABLE => {
                out.push(table()[(t >> 7) as usize][b[0] as usize]);
                continue;
            }
            1..=8 => {
                let mut v = [0u8; 8];
                v[..n].copy_from_slice(b);
                F::from(u64::from_le_bytes(v))
            }
            _ => {
                let mut r = [0u8; 32];
                r[..n].copy_from_slice(b);
                F::from_repr(r.into()).unwrap()
            }
        };
        out.push(if t & 0x80 != 0 { -x } else { x });
    }
}

/// `(tag range, payload offset)` for `k` chunks; a real format would store
/// these offsets in the header.
fn split_compact(tags: &[u8], k: usize) -> Vec<(usize, usize, usize)> {
    let step = tags.len().div_ceil(k);
    let mut chunks = Vec::new();
    let mut off = 0;
    for start in (0..tags.len()).step_by(step) {
        let end = (start + step).min(tags.len());
        chunks.push((start, end, off));
        off += tags[start..end]
            .iter()
            .map(|t| (t & 63) as usize)
            .sum::<usize>();
    }
    chunks
}

fn decode_compact_par<const TABLE: bool>(
    tags: &[u8],
    payload: &[u8],
    chunks: &[(usize, usize, usize)],
) -> Vec<F> {
    let mut out: Vec<F> = Vec::with_capacity(tags.len());
    let parts: Vec<Vec<F>> = std::thread::scope(|s| {
        let hs: Vec<_> = chunks
            .iter()
            .map(|&(a, b, off)| {
                s.spawn(move || decode_compact_t::<TABLE>(&tags[a..b], &payload[off..]))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for p in parts {
        out.extend_from_slice(&p);
    }
    out
}

/// Collects every serde `(u8; 32)` tuple (how halo2curves serializes a field
/// element) and counts the remaining bincode bytes.
#[derive(Default)]
struct Collector {
    scalars: Vec<[u8; 32]>,
    other: u64,
    cur: Option<Vec<u8>>,
}

#[derive(Debug)]
struct Error(String);
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

impl Collector {
    fn add(&mut self, n: u64) {
        self.other += n;
    }
}

#[rustfmt::skip]
impl ser::Serializer for &mut Collector {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn is_human_readable(&self) -> bool { false }
    fn serialize_bool(self, _: bool) -> R { self.add(1); Ok(()) }
    fn serialize_i8(self, _: i8) -> R { self.add(1); Ok(()) }
    fn serialize_i16(self, _: i16) -> R { self.add(2); Ok(()) }
    fn serialize_i32(self, _: i32) -> R { self.add(4); Ok(()) }
    fn serialize_i64(self, _: i64) -> R { self.add(8); Ok(()) }
    fn serialize_i128(self, _: i128) -> R { self.add(16); Ok(()) }
    fn serialize_u8(self, v: u8) -> R {
        match &mut self.cur { Some(c) => c.push(v), None => self.add(1) }
        Ok(())
    }
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
    fn serialize_tuple(self, len: usize) -> Result<Self, Error> {
        if len == 32 && self.cur.is_none() { self.cur = Some(Vec::with_capacity(32)); }
        Ok(self)
    }
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
        impl ser::$trait for &mut Collector {
            type Ok = ();
            type Error = Error;
            fn $method<T: ?Sized + Serialize>(&mut self, v: &T) -> R { v.serialize(&mut **self) }
            fn end(self) -> R { Ok(()) }
        }
    )*};
}

element_impls!(
    SerializeSeq::serialize_element,
    SerializeTupleStruct::serialize_field,
    SerializeTupleVariant::serialize_field
);

impl ser::SerializeTuple for &mut Collector {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> R {
        v.serialize(&mut **self)
    }
    fn end(self) -> R {
        if self.cur.as_ref().is_some_and(|c| c.len() == 32) {
            let c = self.cur.take().unwrap();
            self.scalars.push(c.try_into().unwrap());
        }
        Ok(())
    }
}

impl ser::SerializeMap for &mut Collector {
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

macro_rules! struct_impls {
    ($($trait:ident),*) => {$(
        impl ser::$trait for &mut Collector {
            type Ok = ();
            type Error = Error;
            fn serialize_field<T: ?Sized + Serialize>(&mut self, _: &'static str, v: &T) -> R {
                v.serialize(&mut **self)
            }
            fn end(self) -> R { Ok(()) }
        }
    )*};
}

struct_impls!(SerializeStruct, SerializeStructVariant);
