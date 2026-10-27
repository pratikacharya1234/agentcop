//! Tests for sound playback
//!
//! Key requirement: Sound playback MUST NOT BLOCK verdict return
//! The hook must return JSON within milliseconds; sound plays in background

use cop_siren::SoundEvent;

#[test]
fn sound_events_are_distinct() {
    // All required verdict sounds are defined and distinct
    let allow_sound = SoundEvent::Allow;
    let ask_sound = SoundEvent::Ask;
    let deny_sound = SoundEvent::Deny;

    assert_ne!(allow_sound, ask_sound);
    assert_ne!(ask_sound, deny_sound);
    assert_ne!(allow_sound, deny_sound);
}

#[test]
fn sound_event_matches_work() {
    // Sound events can be pattern-matched
    let event = SoundEvent::Deny;
    let result = matches!(
        event,
        SoundEvent::Allow
            | SoundEvent::Ask
            | SoundEvent::Deny
            | SoundEvent::Honeytoken
            | SoundEvent::Frozen
            | SoundEvent::Gavel
            | SoundEvent::CaseClosed
    );
    assert!(result);
}
