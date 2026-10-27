import pytest

from app.passwords import InvalidHashError, hash_password, parse_hash, verify_password


def test_roundtrip():
    encoded = hash_password("s3cret-password", log_n=10)
    assert encoded.startswith("$scrypt$ln=10,r=8,p=1$")
    assert verify_password("s3cret-password", encoded)
    assert not verify_password("wrong", encoded)
    assert not verify_password("", encoded)


def test_salts_differ():
    assert hash_password("same", log_n=10) != hash_password("same", log_n=10)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "plain",
        "$scrypt$ln=99,r=8,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
        "$bcrypt$x$y$z",
        "$scrypt$ln=10$a$b",
    ],
)
def test_rejects_malformed(bad):
    with pytest.raises(InvalidHashError):
        parse_hash(bad)


def test_rejects_oversized_password():
    with pytest.raises(ValueError):
        hash_password("x" * 2000)
