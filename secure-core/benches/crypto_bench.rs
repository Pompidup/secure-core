use std::io::Cursor;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use secure_core::crypto::{decrypt_bytes, encrypt_bytes, Dek};
use secure_core::streaming::{decrypt_stream, encrypt_stream};

const BENCH_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

fn bench_encrypt_in_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_bytes");

    for size in [1024, 1024 * 1024] {
        let label = if size == 1024 { "1KB" } else { "1MB" };
        let data = random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| encrypt_bytes(data, &BENCH_KEY).unwrap());
        });
    }

    group.finish();
}

fn bench_decrypt_in_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_bytes");

    let data_1mb = random_bytes(1024 * 1024);
    let blob_1mb = encrypt_bytes(&data_1mb, &BENCH_KEY).unwrap();

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("1MB", |b| {
        b.iter(|| decrypt_bytes(&blob_1mb, &BENCH_KEY).unwrap());
    });

    group.finish();
}

fn bench_encrypt_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_stream");

    let data_50mb = random_bytes(50 * 1024 * 1024);
    let dek = Dek::new(BENCH_KEY);

    group.throughput(Throughput::Bytes(50 * 1024 * 1024));
    group.sample_size(10);
    group.bench_function("50MB", |b| {
        b.iter(|| {
            let mut output = Vec::new();
            encrypt_stream(Cursor::new(&data_50mb), &mut output, &dek).unwrap();
        });
    });

    group.finish();
}

fn bench_decrypt_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_stream");

    let data_50mb = random_bytes(50 * 1024 * 1024);
    let dek = Dek::new(BENCH_KEY);
    let mut encrypted = Vec::new();
    encrypt_stream(Cursor::new(&data_50mb), &mut encrypted, &dek).unwrap();

    group.throughput(Throughput::Bytes(50 * 1024 * 1024));
    group.sample_size(10);
    group.bench_function("50MB", |b| {
        b.iter(|| {
            let mut output = Vec::new();
            decrypt_stream(Cursor::new(&encrypted), &mut output, &dek).unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt_in_memory,
    bench_decrypt_in_memory,
    bench_encrypt_stream,
    bench_decrypt_stream,
);
criterion_main!(benches);
