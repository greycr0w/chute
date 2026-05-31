"""Tests for subdomain label generation (names.random_phrase / random_label)."""

from chute import names


def test_random_phrase_is_valid_label():
    for _ in range(300):
        p = names.random_phrase()
        assert names.valid_label(p), p


def test_random_phrase_shape():
    parts = names.random_phrase().split("-")
    assert len(parts) == 3
    adj1, adj2, noun = parts
    assert adj1 != adj2  # two distinct adjectives
    assert adj1 in names._ADJECTIVES
    assert adj2 in names._ADJECTIVES
    assert noun in names._NOUNS


def test_random_phrase_varies():
    # ~440k combinations -> 50 draws must not collapse to a single value.
    assert len({names.random_phrase() for _ in range(50)}) > 1


def test_random_label_still_valid():
    assert names.valid_label(names.random_label())
