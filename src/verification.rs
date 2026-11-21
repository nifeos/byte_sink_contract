//! **Machine-checked proofs (Kani) of the byte-sink framing**: the decoder is total, and the five
//! properties a sink implementer relies on hold for every input, not the sampled ones the unit
//! tests pin. Behind `#[cfg(kani)]`, so only `cargo kani` compiles them.

use super::*;

/// Falsification: replayable `falsifications/verification.any_prefix_survives_pack_then_unpack.patch`
/// **Any prefix of up to sixteen symbolic bytes survives `pack` then `unpack`**, with `taken` equal
/// to its length. A concrete loop over the seventeen lengths, since a symbolic length does not
/// finish.
#[kani::proof]
#[kani::unwind(18)]
fn any_prefix_survives_pack_then_unpack() {
    let src: [u8; MAXIMUM_INLINE_BYTES] = kani::any();
    let mut n = 0;
    while n <= MAXIMUM_INLINE_BYTES {
        let (
            MessageWords {
                word_zero,
                word_one,
                word_two,
            },
            taken,
        ) = pack(&src[..n]);
        assert_eq!(taken, n);
        let mut out = [0u8; MAXIMUM_INLINE_BYTES];
        assert_eq!(
            unpack(MessageWords::new(word_zero, word_one, word_two), &mut out),
            Message::Bytes(n)
        );
        assert_eq!(out[..n], src[..n]);
        n += 1;
    }
}

/// Falsification: replayable `falsifications/verification.unpack_never_answers_more_than_a_message_holds.patch`
/// **`unpack` never answers more bytes than a message holds**, for any three words.
#[kani::proof]
fn unpack_never_answers_more_than_a_message_holds() {
    let (word_zero, word_one, word_two): (u64, u64, u64) = kani::any();
    let mut out = [0u8; MAXIMUM_INLINE_BYTES];
    if let Message::Bytes(n) = unpack(MessageWords::new(word_zero, word_one, word_two), &mut out) {
        assert!(n <= MAXIMUM_INLINE_BYTES);
    }
}

/// Falsification: replayable `falsifications/verification.severity_reads_back_clamped_and_leaves_the_rest.patch`
/// **`with_severity` then `severity` reads back the clamped level**, and leaves the count, the
/// opcode and the kind of any first word unchanged.
#[kani::proof]
fn severity_reads_back_clamped_and_leaves_the_rest() {
    let word_zero: u64 = kani::any();
    let level: u8 = kani::any();
    let marked = with_severity(word_zero, level);
    assert_eq!(severity(marked), Some(level.min(7)));
    assert_eq!(len(marked), len(word_zero));
    assert_eq!(operation(marked), operation(word_zero));
    assert_eq!(kind(marked), kind(word_zero));
}

/// Falsification: replayable `falsifications/verification.classify_separates_the_three_outcomes.patch`
/// **`classify` is `Gone` exactly for [`GONE`] and `Ok` exactly for a non-negative return.**
#[kani::proof]
fn classify_separates_the_three_outcomes() {
    let returned: i64 = kani::any();
    assert_eq!(classify(returned) == Sent::Ok, returned >= 0);
    assert_eq!(classify(returned) == Sent::Gone, returned == GONE);
}

/// Falsification: replayable `falsifications/verification.an_end_of_stream_decodes_exactly_from_its_one_message.patch`
/// **An end of stream decodes from exactly one message**: over every three words, [`unpack`]
/// answers [`Message::EndOfStream`] if and only if they are `(end_of_stream(), 0, 0)`.
#[kani::proof]
fn an_end_of_stream_decodes_exactly_from_its_one_message() {
    let word_zero: u64 = kani::any();
    let word_one: u64 = kani::any();
    let word_two: u64 = kani::any();
    let mut out = [0u8; MAXIMUM_INLINE_BYTES];
    let decoded = unpack(MessageWords::new(word_zero, word_one, word_two), &mut out);
    assert_eq!(
        decoded == Message::EndOfStream,
        (word_zero, word_one, word_two) == (end_of_stream(), 0, 0)
    );
}

/// Falsification: replayable `falsifications/verification.end_of_stream_is_no_bytes_message.patch`
/// **An end-of-stream first word equals no bytes message of any length.**
#[kani::proof]
fn end_of_stream_is_no_bytes_message() {
    let n: u32 = kani::any();
    kani::assume(n <= MAXIMUM_INLINE_BYTES as u32);
    assert_ne!(end_of_stream(), first_word(OPERATION_BYTES, n));
}
