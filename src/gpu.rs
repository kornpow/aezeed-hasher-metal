use anyhow::{anyhow, bail, ensure, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use metal::*;

pub struct MetalSearch {
    device: Device,
    queue: CommandQueue,
    pipeline: ComputePipelineState,
    table: Buffer,
    input: Buffer,
    output: Buffer,
    winner: Buffer,
    prefix: Buffer,
    capacity: usize,
    pub threads_per_group: u64,
    pub window_bits: u32,
}

impl MetalSearch {
    pub fn new(capacity: usize, threads: Option<u64>) -> Result<Self> {
        Self::with_window(capacity, threads, 8)
    }

    pub fn with_window(capacity: usize, threads: Option<u64>, window_bits: u32) -> Result<Self> {
        ensure!(
            matches!(window_bits, 2 | 4 | 8),
            "curve window must be 2, 4, or 8 bits"
        );
        ensure!(
            (1..=1_048_576).contains(&capacity),
            "batch size must be 1..1048576"
        );
        let device = Device::system_default()
            .or_else(|| Device::all().into_iter().next())
            .ok_or_else(|| {
                anyhow!("no Metal GPU available (default device and device enumeration are empty)")
            })?;
        let source = include_str!("../shaders/search.metal").replace(
            "#include \"sha512-constants.metal\"",
            include_str!("../shaders/sha512-constants.metal"),
        );
        let library = device
            .new_library_with_source(&source, &CompileOptions::new())
            .map_err(|e| anyhow!("Metal compilation failed: {e}"))?;
        let kernel = library
            .get_function("search", None)
            .map_err(|e| anyhow!(e))?;
        let pipeline = device
            .new_compute_pipeline_state_with_function(&kernel)
            .map_err(|e| anyhow!(e))?;
        let width = pipeline.thread_execution_width();
        let threads_per_group = threads.unwrap_or(width);
        ensure!(
            threads_per_group <= pipeline.max_total_threads_per_threadgroup(),
            "threadgroup size exceeds this pipeline's limit of {}",
            pipeline.max_total_threads_per_threadgroup()
        );
        ensure!(
            threads_per_group > 0 && threads_per_group % width == 0,
            "threadgroup size must be a multiple of {width}"
        );
        let secp = Secp256k1::new();
        let mut words = Vec::<u32>::new();
        for window in 0..256 / window_bits {
            for digit in 1..1u32 << window_bits {
                let mut bytes = [0; 32];
                let bit = window * window_bits;
                bytes[31 - (bit / 8) as usize] = (digit << (bit % 8)) as u8;
                let secret = SecretKey::from_slice(&bytes)?;
                let pk = PublicKey::from_secret_key(&secp, &secret).serialize_uncompressed();
                for coordinate in [&pk[1..33], &pk[33..65]] {
                    for chunk in coordinate.rchunks_exact(4) {
                        words.push(u32::from_be_bytes(chunk.try_into()?));
                    }
                }
            }
        }
        let shared = MTLResourceOptions::StorageModeShared;
        let table =
            device.new_buffer_with_data(words.as_ptr().cast(), (words.len() * 4) as u64, shared);
        Ok(Self {
            queue: device.new_command_queue(),
            table,
            input: device.new_buffer((capacity * 16) as u64, shared),
            output: device.new_buffer((capacity * 418) as u64, shared),
            winner: device.new_buffer(4, shared),
            prefix: device.new_buffer(8, shared),
            device,
            pipeline,
            capacity,
            threads_per_group,
            window_bits,
        })
    }

    pub fn name(&self) -> &str {
        self.device.name()
    }

    pub fn run(
        &mut self,
        entropy: &[[u8; 16]],
        coin: u32,
        prefix: &[u8],
        debug: bool,
    ) -> Result<(Option<usize>, Vec<u8>)> {
        ensure!(
            !entropy.is_empty() && entropy.len() <= self.capacity,
            "batch exceeds capacity"
        );
        ensure!(prefix.len() <= 8, "prefix too long");
        unsafe {
            std::ptr::copy_nonoverlapping(
                entropy.as_ptr().cast::<u8>(),
                self.input.contents().cast(),
                entropy.len() * 16,
            );
            std::ptr::copy_nonoverlapping(
                prefix.as_ptr(),
                self.prefix.contents().cast(),
                prefix.len(),
            );
            self.winner.contents().cast::<u32>().write(u32::MAX);
            std::ptr::write_bytes(self.output.contents().cast::<u8>(), 0, entropy.len() * 418);
        }
        let params = [
            entropy.len() as u32,
            coin,
            prefix.len() as u32,
            u32::from(debug),
        ];
        objc::rc::autoreleasepool(|| {
            let command = self.queue.new_command_buffer();
            let encoder = command.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.pipeline);
            encoder.set_buffer(0, Some(&self.input), 0);
            encoder.set_buffer(1, Some(&self.output), 0);
            encoder.set_bytes(2, 16, params.as_ptr().cast());
            encoder.set_buffer(3, Some(&self.prefix), 0);
            encoder.set_buffer(4, Some(&self.table), 0);
            encoder.set_buffer(5, Some(&self.winner), 0);
            encoder.set_bytes(6, 4, (&self.window_bits as *const u32).cast());
            encoder.dispatch_threads(
                MTLSize::new(entropy.len() as u64, 1, 1),
                MTLSize::new(self.threads_per_group, 1, 1),
            );
            encoder.end_encoding();
            command.commit();
            command.wait_until_completed();
            if command.status() != MTLCommandBufferStatus::Completed {
                bail!(
                    "Metal command did not complete successfully: {:?}",
                    command.status()
                );
            }
            let index = unsafe { self.winner.contents().cast::<u32>().read() };
            let count = if debug { entropy.len() * 418 } else { 33 };
            let bytes =
                unsafe { std::slice::from_raw_parts(self.output.contents().cast::<u8>(), count) }
                    .to_vec();
            Ok(((index != u32::MAX).then_some(index as usize), bytes))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive;
    #[test]
    fn metal_matches_every_bip32_stage() {
        let samples: Vec<[u8; 16]> = (0..33)
            .map(|i| {
                let mut e = [i; 16];
                e[0] = 255 - i;
                e
            })
            .collect();
        for window_bits in [2, 4, 8] {
            let mut gpu = MetalSearch::with_window(33, None, window_bits).unwrap();
            for coin in [0, 1] {
                let (_, output) = gpu.run(&samples, coin, &[], true).unwrap();
                for (i, entropy) in samples.iter().enumerate() {
                    let (pk, stages) = derive::derive(entropy, coin).unwrap();
                    let record = &output[i * 418..(i + 1) * 418];
                    assert_eq!(record[0], 1, "invalid candidate {i}");
                    for (j, stage) in stages.iter().enumerate() {
                        assert_eq!(
                            &record[1 + j * 64..33 + j * 64],
                            &stage.secret,
                            "secret candidate {i}, stage {j}"
                        );
                        assert_eq!(
                            &record[33 + j * 64..65 + j * 64],
                            &stage.chain_code,
                            "chain candidate {i}, stage {j}"
                        );
                    }
                    assert_eq!(&record[385..418], &pk, "pubkey candidate {i}");
                }
            }
            let expected = derive::derive(&samples[17], 0).unwrap().0;
            let (winner, bytes) = gpu.run(&samples, 0, &expected[..4], false).unwrap();
            assert_eq!(winner, Some(17));
            assert_eq!(bytes, expected);
            assert!(gpu
                .run(&samples, 0, &[0xff, 0xff], false)
                .unwrap()
                .0
                .is_none());
            // Multiple matching invocations contend for the same winner slot.
            let duplicates = vec![samples[17]; 33];
            let (winner, bytes) = gpu.run(&duplicates, 0, &expected[..2], false).unwrap();
            assert!(winner.is_some_and(|i| i < duplicates.len()));
            assert_eq!(bytes, expected);
        }
    }
}
