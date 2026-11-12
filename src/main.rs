use aezeed_hasher_metal::{aezeed, derive};
use anyhow::{ensure, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rand::{rngs::OsRng, RngCore};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    version,
    about = "LND vanity node identities using Rust and Apple Metal"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Search for an aezeed whose node public key starts with a hex prefix.
    Vanitygen {
        #[arg(long)]
        prefix: String,
        #[command(flatten)]
        options: Options,
    },
    /// Measure complete candidate throughput, including entropy generation.
    Benchmark {
        #[arg(long, default_value_t = 5)]
        seconds: u64,
        #[command(flatten)]
        options: Options,
    },
    /// Compare all GPU intermediate keys and final public keys with the CPU.
    VerifyGpu {
        #[arg(long, default_value_t = 256)]
        samples: usize,
        #[command(flatten)]
        options: Options,
    },
    /// Derive a node public key from explicitly supplied 16-byte entropy.
    Derive {
        #[arg(long)]
        entropy: String,
        #[arg(long,value_enum,default_value_t=Network::Mainnet)]
        network: Network,
    },
}
#[derive(Args)]
struct Options {
    #[arg(long,value_enum,default_value_t=Backend::Metal)]
    backend: Backend,
    #[arg(long,value_enum,default_value_t=Network::Mainnet)]
    network: Network,
    /// Candidates per batch (default: Metal 16384, CPU 4096).
    #[arg(long)]
    batch_size: Option<usize>,
    #[arg(long, default_value_t = 4)]
    threads: usize,
    #[arg(long)]
    threadgroup_size: Option<u64>,
    /// Preweighted secp256k1 table window: 2, 4, or 8 bits.
    #[arg(long, default_value_t = 8)]
    window_bits: u32,
}

impl Options {
    fn batch_size(&self) -> usize {
        self.batch_size.unwrap_or(match self.backend {
            Backend::Metal => 16384,
            Backend::Cpu => 4096,
        })
    }
}
#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    Cpu,
    Metal,
}
#[derive(Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}
impl Network {
    fn coin(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            _ => 1,
        }
    }
}

struct Engine {
    #[cfg(target_os = "macos")]
    gpu: Option<aezeed_hasher_metal::gpu::MetalSearch>,
    threads: usize,
}
impl Engine {
    fn new(options: &Options) -> Result<Self> {
        let batch_size = options.batch_size();
        ensure!(
            (1..=1_048_576).contains(&batch_size),
            "batch size must be 1..1048576"
        );
        ensure!(
            (1..=1024).contains(&options.threads),
            "CPU threads must be 1..1024"
        );
        #[cfg(target_os = "macos")]
        let gpu = if matches!(options.backend, Backend::Metal) {
            let gpu = aezeed_hasher_metal::gpu::MetalSearch::with_window(
                batch_size,
                options.threadgroup_size,
                options.window_bits,
            )?;
            eprintln!(
                "GPU: {}, batch size {}, threadgroup size {}, curve window {} bits",
                gpu.name(),
                batch_size,
                gpu.threads_per_group,
                gpu.window_bits
            );
            Some(gpu)
        } else {
            None
        };
        #[cfg(not(target_os = "macos"))]
        ensure!(
            matches!(options.backend, Backend::Cpu),
            "Metal requires macOS"
        );
        Ok(Self {
            #[cfg(target_os = "macos")]
            gpu,
            threads: options.threads,
        })
    }
    fn batch(
        &mut self,
        seeds: &[[u8; 16]],
        coin: u32,
        prefix: &[u8],
    ) -> Result<Option<(usize, [u8; 33])>> {
        #[cfg(target_os = "macos")]
        if let Some(gpu) = &mut self.gpu {
            let (index, pk) = gpu.run(seeds, coin, prefix, false)?;
            return index
                .map(|i| Ok((i, pk.as_slice().try_into()?)))
                .transpose();
        }
        let chunk = seeds.len().div_ceil(self.threads);
        let matches = std::thread::scope(|scope| {
            let workers: Vec<_> = seeds
                .chunks(chunk)
                .enumerate()
                .map(|(n, seeds)| {
                    scope.spawn(move || {
                        let mut found = None;
                        for (i, entropy) in seeds.iter().enumerate() {
                            if let Ok((pk, _)) = derive::derive(entropy, coin) {
                                if !prefix.is_empty() && pk.starts_with(prefix) && found.is_none() {
                                    found = Some((n * chunk + i, pk));
                                }
                            }
                        }
                        found
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|h| h.join().expect("CPU worker panicked"))
                .find_map(|x| x)
        });
        Ok(matches)
    }
}

fn run_search(options: Options, prefix: Option<String>, seconds: Option<u64>) -> Result<()> {
    let benchmarking = seconds.is_some();
    let prefix = prefix
        .map(|s| derive::prefix(&s))
        .transpose()?
        // A real, difficult prefix keeps the full GPU public-key calculation
        // observable to the compiler and makes benchmark work match search work.
        .unwrap_or_else(|| vec![0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    ensure!(seconds != Some(0), "benchmark duration must be positive");
    let mut engine = Engine::new(&options)?;
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::Relaxed);
    })?;
    let mut seeds = vec![[0; 16]; options.batch_size()];
    let start = Instant::now();
    let mut total = 0u64;
    let mut last = Instant::now();
    while !stop.load(Ordering::Relaxed)
        && seconds.is_none_or(|s| start.elapsed() < Duration::from_secs(s))
    {
        OsRng.try_fill_bytes(seeds.as_flattened_mut())?;
        let found = engine.batch(&seeds, options.network.coin(), &prefix)?;
        total += seeds.len() as u64;
        if let Some((index, gpu_pk)) = found.filter(|_| !benchmarking) {
            ensure!(index < seeds.len(), "GPU returned invalid candidate index");
            let (pk, _) = derive::derive(&seeds[index], options.network.coin())?;
            ensure!(
                pk == gpu_pk && pk.starts_with(&prefix),
                "candidate failed independent CPU verification"
            );
            let mnemonic = aezeed::generate(seeds[index])?;
            let (restored, _) = aezeed::decode(&mnemonic, &[])?;
            ensure!(
                derive::derive(&restored, options.network.coin())?.0 == pk,
                "mnemonic restoration mismatch"
            );
            eprintln!(
                "\nVerified match after {total} candidates in {:.2}s",
                start.elapsed().as_secs_f64()
            );
            println!("Public key: {}\nAezeed: {mnemonic}", hex::encode(pk));
            return Ok(());
        }
        if last.elapsed() >= Duration::from_secs(1) {
            let elapsed = start.elapsed().as_secs_f64();
            eprint!(
                "\rTested {total}, {:.0} seeds/s, {elapsed:.1}s",
                total as f64 / elapsed
            );
            if !benchmarking {
                eprint!(
                    ", chance of a match by now {:.2}%",
                    derive::success_probability(total, prefix.len()) * 100.0
                );
            }
            last = Instant::now();
        }
    }
    eprintln!();
    println!(
        "Candidates: {total}\nElapsed: {:.3}s\nSeeds/s: {:.0}",
        start.elapsed().as_secs_f64(),
        total as f64 / start.elapsed().as_secs_f64()
    );
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Vanitygen { prefix, options } => run_search(options, Some(prefix), None),
        Command::Benchmark { seconds, options } => run_search(options, None, Some(seconds)),
        Command::Derive { entropy, network } => {
            let bytes: [u8; 16] = hex::decode(entropy)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("entropy must be exactly 16 bytes"))?;
            println!("{}", hex::encode(derive::derive(&bytes, network.coin())?.0));
            Ok(())
        }
        Command::VerifyGpu {
            samples,
            mut options,
        } => {
            ensure!(
                (1..=1_048_576).contains(&samples),
                "samples must be 1..1048576"
            );
            options.backend = Backend::Metal;
            let batch_size = options.batch_size();
            #[cfg(target_os = "macos")]
            {
                let mut gpu = aezeed_hasher_metal::gpu::MetalSearch::with_window(
                    batch_size,
                    options.threadgroup_size,
                    options.window_bits,
                )?;
                let mut checked = 0;
                while checked < samples {
                    let n = batch_size.min(samples - checked);
                    let mut seeds = vec![[0u8; 16]; n];
                    OsRng.try_fill_bytes(seeds.as_flattened_mut())?;
                    let (_, output) = gpu.run(&seeds, options.network.coin(), &[], true)?;
                    for (i, seed) in seeds.iter().enumerate() {
                        let (pk, stages) = derive::derive(seed, options.network.coin())?;
                        let r = &output[i * 418..(i + 1) * 418];
                        ensure!(r[0] == 1, "GPU rejected valid candidate");
                        for (j, s) in stages.iter().enumerate() {
                            ensure!(
                                r[1 + j * 64..33 + j * 64] == s.secret
                                    && r[33 + j * 64..65 + j * 64] == s.chain_code,
                                "GPU mismatch at candidate {}, stage {j}",
                                checked + i
                            );
                        }
                        ensure!(r[385..418] == pk, "GPU public key mismatch");
                    }
                    checked += n;
                }
                println!("Verified {checked} GPU derivations against CPU, including every intermediate key and chain code");
                Ok(())
            }
            #[cfg(not(target_os = "macos"))]
            anyhow::bail!("Metal requires macOS")
        }
    }
}
