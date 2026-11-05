// macOS system audio capture via ScreenCaptureKit (no driver install needed).

use anyhow::{Context, Result};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
use std::time::Duration;

use screencapturekit_sys::cm_sample_buffer_ref::CMSampleBufferRef;
use screencapturekit_sys::content_filter::{UnsafeContentFilter, UnsafeInitParams};
use screencapturekit_sys::shareable_content::UnsafeSCShareableContent;
use screencapturekit_sys::stream_error_handler::UnsafeSCStreamError;
use screencapturekit_sys::stream::UnsafeSCStream;
use screencapturekit_sys::stream_configuration::UnsafeStreamConfiguration;
use screencapturekit_sys::stream_output_handler::UnsafeSCStreamOutput;

pub struct AudioFrame {
    pub pts: i64,
    /// Interleaved float32 samples.
    pub data: Vec<f32>,
    pub channels: u32,
}

struct ErrorHandler;
impl UnsafeSCStreamError for ErrorHandler {
    fn handle_error(&self) {
        eprintln!("stream error");
    }
}

struct OutputHandler {
    tx: SyncSender<AudioFrame>,
}

impl UnsafeSCStreamOutput for OutputHandler {
    fn did_output_sample_buffer(&self, sample: objc_id::Id<CMSampleBufferRef>, _of_type: u8) {
        let buffers = sample.get_av_audio_buffer_list();
        let mut data = Vec::new();
        let mut channels = 2u32;
        for b in buffers {
            channels = b.number_channels.max(1);
            data.extend(
                b.data
                    .chunks_exact(4)
                    .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])),
            );
        }
        let _ = self.tx.send(AudioFrame {
            pts: sample.get_presentation_timestamp().value,
            data,
            channels,
        });
    }
}

/// Stream system audio indefinitely; invokes `f` on every frame until
/// `stop` is set. Requires Screen Recording permission.
pub fn capture_stream<F>(stop: &std::sync::atomic::AtomicBool, mut f: F) -> Result<()>
where
    F: FnMut(&AudioFrame) + Send + 'static,
{
    let content = unsafe { UnsafeSCShareableContent::get() }
        .map_err(|e| anyhow::anyhow!("SCShareableContent: {e:?}"))
        .context("screen recording permission may be missing")?;

    let display = unsafe { content.displays() }
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no display found"))?;
    let filter = unsafe { UnsafeContentFilter::init(UnsafeInitParams::Display(display)) };

    let config = UnsafeStreamConfiguration {
        width: 2,
        height: 2,
        captures_audio: 1,
        excludes_current_process_audio: 1,
        queue_depth: 8,
        ..Default::default()
    };

    let (tx, rx) = sync_channel::<AudioFrame>(4096);
    let stream = unsafe {
        UnsafeSCStream::init(filter, config.into(), ErrorHandler {})
    };
    unsafe { stream.add_stream_output(OutputHandler { tx }, 1) }; // 1 = audio
    unsafe { stream.start_capture() }.map_err(|e| anyhow::anyhow!("start: {e}"))?;

    let _keep = &stream;
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(frame) => f(&frame),
            Err(_) => continue,
        }
    }
    unsafe { stream.stop_capture() }.map_err(|e| anyhow::anyhow!("stop: {e}"))?;
    Ok(())
}

/// Capture system audio for `duration`, invoking `f` on every frame.
/// Requires Screen Recording permission (System Settings > Privacy > Screen Recording).
pub fn capture<F: FnMut(&AudioFrame) + Send + 'static>(duration: Duration, mut f: F) -> Result<()> {
    let content = unsafe { UnsafeSCShareableContent::get() }
        .map_err(|e| anyhow::anyhow!("SCShareableContent: {e}"))
        .context("screen recording permission may be missing")?;

    let display = unsafe { content.displays() }
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no display found"))?;
    let filter = unsafe { UnsafeContentFilter::init(UnsafeInitParams::Display(display)) };

    let config = UnsafeStreamConfiguration {
        width: 2,
        height: 2,
        captures_audio: 1,
        excludes_current_process_audio: 1,
        queue_depth: 8,
        ..Default::default()
    };

    let (tx, rx) = sync_channel::<AudioFrame>(1024);
    let stream = unsafe {
        UnsafeSCStream::init(filter, config.into(), ErrorHandler {})
    };
    unsafe { stream.add_stream_output(OutputHandler { tx }, 1) }; // 1 = audio
    unsafe { stream.start_capture() }.map_err(|e| anyhow::anyhow!("start: {e}"))?;

    // Drain frames on this thread until deadline.
    let deadline = std::time::Instant::now() + duration;
    while let Ok(frame) = rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
        f(&frame);
    }

    unsafe { stream.stop_capture() }.map_err(|e| anyhow::anyhow!("stop: {e}"))?;
    drop(stream);
    Ok(())
}
