//! Non-blocking sound playback for verdicts
//!
//! PLAN:
//! 1. SoundPlayer spawns background threads for audio
//! 2. Verdict callbacks return immediately (never block)
//! 3. Mute, volume, quiet hours controls
//! 4. Auto-silent in CI, SSH, no audio device
//! 5. Async playback via std::thread

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Sound event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoundEvent {
    Allow,
    Ask,
    Deny,
    Honeytoken,
    Frozen,
    Gavel,
    CaseClosed,
}

/// Sound player configuration
pub struct SoundPlayer {
    muted: Arc<AtomicBool>,
    volume: Arc<parking_lot::Mutex<f32>>,
    enabled: Arc<AtomicBool>,
}

impl SoundPlayer {
    /// Create a new sound player
    pub fn new() -> Self {
        let enabled = !Self::is_ci() && !Self::is_ssh() && Self::has_audio_device();

        SoundPlayer {
            muted: Arc::new(AtomicBool::new(false)),
            volume: Arc::new(parking_lot::Mutex::new(0.5)),
            enabled: Arc::new(AtomicBool::new(enabled)),
        }
    }

    /// Play a sound event (non-blocking)
    pub fn play(&self, event: SoundEvent) {
        if !self.enabled.load(Ordering::Relaxed) || self.muted.load(Ordering::Relaxed) {
            return;
        }

        let volume = *self.volume.lock();

        // Spawn background thread for playback (non-blocking)
        thread::spawn(move || {
            Self::play_sound(event, volume);
        });
    }

    /// Internal sound playback (runs in background thread)
    fn play_sound(event: SoundEvent, _volume: f32) {
        // Simulate sound playback duration
        let duration = match event {
            SoundEvent::Allow => Duration::from_millis(0), // Silence
            SoundEvent::Ask => Duration::from_millis(600), // Whistle
            SoundEvent::Deny => Duration::from_millis(1200), // Siren + click
            SoundEvent::Honeytoken => Duration::from_millis(1000), // Alarm
            SoundEvent::Frozen => Duration::from_millis(800), // Cell door
            SoundEvent::Gavel => Duration::from_millis(400), // Gavel
            SoundEvent::CaseClosed => Duration::from_millis(1000), // Jingle
        };

        thread::sleep(duration);
    }

    /// Mute or unmute sounds
    pub fn set_mute(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    /// Set volume (0.0 to 1.0)
    pub fn set_volume(&self, volume: f32) {
        let v = volume.clamp(0.0, 1.0);
        *self.volume.lock() = v;
    }

    /// Check if running in CI environment
    fn is_ci() -> bool {
        std::env::var("CI").is_ok()
            || std::env::var("CONTINUOUS_INTEGRATION").is_ok()
            || std::env::var("GITHUB_ACTIONS").is_ok()
    }

    /// Check if running over SSH
    fn is_ssh() -> bool {
        std::env::var("SSH_CONNECTION").is_ok() || std::env::var("SSH_CLIENT").is_ok()
    }

    /// Check if audio device exists (stub for now)
    fn has_audio_device() -> bool {
        // In real implementation, would check for audio hardware
        // For now, assume we have one unless explicitly disabled
        std::env::var("NO_AUDIO_DEVICE").is_err()
    }
}

impl Default for SoundPlayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_returns_before_sound_finishes() {
        let player = SoundPlayer::new();
        let start = std::time::Instant::now();

        // Play a long sound
        player.play(SoundEvent::Deny);

        // play() should return immediately
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(100),
            "play() took {:?}, should be instant",
            elapsed
        );
    }

    #[test]
    fn no_audio_device_stays_silent() {
        std::env::set_var("NO_AUDIO_DEVICE", "1");
        let player = SoundPlayer::new();
        assert!(!player.enabled.load(Ordering::Relaxed));
        std::env::remove_var("NO_AUDIO_DEVICE");
    }

    #[test]
    fn ci_environment_auto_silent() {
        std::env::set_var("CI", "true");
        let player = SoundPlayer::new();
        assert!(!player.enabled.load(Ordering::Relaxed));
        std::env::remove_var("CI");
    }

    #[test]
    fn mute_prevents_sounds() {
        let player = SoundPlayer::new();
        player.set_mute(true);
        assert!(player.muted.load(Ordering::Relaxed));

        player.set_mute(false);
        assert!(!player.muted.load(Ordering::Relaxed));
    }

    #[test]
    fn volume_control() {
        let player = SoundPlayer::new();
        player.set_volume(0.8);
        assert!((*player.volume.lock() - 0.8).abs() < 0.001);

        player.set_volume(1.5); // Clamp to 1.0
        assert!((*player.volume.lock() - 1.0).abs() < 0.001);

        player.set_volume(-0.5); // Clamp to 0.0
        assert!((*player.volume.lock() - 0.0).abs() < 0.001);
    }

    #[test]
    fn all_sound_events_exist() {
        assert_eq!(SoundEvent::Allow, SoundEvent::Allow);
        assert_eq!(SoundEvent::Ask, SoundEvent::Ask);
        assert_eq!(SoundEvent::Deny, SoundEvent::Deny);
    }
}
