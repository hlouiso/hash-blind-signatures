"""Exercise the actual process boundary, state persistence and signer locking.

The stateful key has the fixed XMSS height 24: keygen sweeps its 2^24 leaves,
a few minutes on 8 cores, once. The cache-rebuild checks run on the stateless
key, whose rebuild takes seconds."""
import pathlib
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())


def cache_is_rebuilt(directory, run):
    """A missing or corrupted signer_cache.bin only costs time."""
    cache_file = directory / "signer_cache.bin"
    cache = cache_file.read_bytes()
    bad = bytearray(cache)
    bad[len(bad) // 2] ^= 1
    cache_file.write_bytes(bytes(bad))
    assert "rebuilt" in run("sign").stdout
    assert cache_file.read_bytes() == cache, "the rebuilt cache is the original"
    run("prove")
    cache_file.unlink()
    assert "rebuilt" in run("sign").stdout
    assert cache_file.read_bytes() == cache
    assert "from signer_cache.bin" in run("sign").stdout
    run("prove")
with tempfile.TemporaryDirectory(prefix="voleith-cli-") as tmp:
    directory = pathlib.Path(tmp)
    message = directory / "message"
    message.write_bytes(b"blind signature CLI integration test")

    def run(*args, ok=True):
        result = subprocess.run([binary, *map(str, args), "-d", tmp], capture_output=True, text=True)
        assert (result.returncode == 0) == ok, result.stdout + result.stderr
        return result

    assert "height=24 capacity=16777216" in run("keygen").stdout
    original = (directory / "signer_key.bin").read_bytes()
    # The cache holds levels 8..24, so sign rebuilds one 256-leaf subtree.
    assert len((directory / "signer_cache.bin").read_bytes()) == 10 + 16 * ((1 << 17) - 1) + 32
    run("keygen", ok=False)
    assert (directory / "signer_key.bin").read_bytes() == original
    run("commit", message)
    assert "from signer_cache.bin" in run("sign").stdout
    run("prove")
    run("verify", message)
    message.write_bytes(b"different")
    run("verify", message, ok=False)
    # Atomic state replacement must not break the shared signer lock.
    processes = [subprocess.Popen([binary, "sign", "-d", tmp], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) for _ in range(2)]
    outputs = [p.communicate() for p in processes]
    assert all(p.returncode == 0 for p in processes), outputs
    assert sorted(int(o.split("Consumed XMSS leaf ")[1].split()[0]) for o, _ in outputs) == [1, 2]
    assert int.from_bytes((directory / "signer_key.bin").read_bytes()[57:65], "little") == 3
    assert "unknown or incomplete argument: --height" in run("keygen", "--height", 10,
                                                             ok=False).stderr
    run("params")
    stateful_state = (directory / "user_state.bin").read_bytes()

# Stateless keys (SLH-DSA-SHAKE-128-24): about a minute of signer work in all.
with tempfile.TemporaryDirectory(prefix="voleith-cli-slh-") as tmp:
    directory = pathlib.Path(tmp)
    message = directory / "message"
    message.write_bytes(b"stateless blind signature CLI integration test")

    def run(*args, ok=True):
        result = subprocess.run([binary, *map(str, args), "-d", tmp], capture_output=True, text=True)
        assert (result.returncode == 0) == ok, result.stdout + result.stderr
        return result

    assert "mutually exclusive" in run("keygen", "--stateful", "--stateless", ok=False).stderr
    assert "run keygen first" in run("commit", message, ok=False).stderr
    run("keygen", "--stateless")
    key = (directory / "signer_key.bin").read_bytes()
    assert key[:8] == b"HBVO001k"
    run("keygen", "--stateless", ok=False)
    assert "keygen options" in run("sign", "--stateless", ok=False).stderr
    run("commit", message)
    assert "from signer_cache.bin" in run("sign").stdout
    first = (directory / "slh_sig.bin").read_bytes()
    run("sign")
    assert (directory / "signer_key.bin").read_bytes() == key, "a stateless key is never rewritten"
    assert (directory / "slh_sig.bin").read_bytes() != first, "signatures are hedged"
    assert not (directory / "xmss_sig.bin").exists()
    run("prove")
    assert "[PASS]" in run("verify", message).stdout
    message.write_bytes(b"different")
    run("verify", message, ok=False)
    cache_is_rebuilt(directory, run)
    # A state committed for the other scheme is refused with a clear error.
    (directory / "user_state.bin").write_bytes(stateful_state)
    assert "run commit again" in run("prove", ok=False).stderr
print("CLI round trips in both schemes, invalid message, atomic state, concurrent "
      "signing, tree caches and scheme checks passed")
