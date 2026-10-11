"""Exercise the actual process boundary, state persistence and signer locking."""
import pathlib
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix="voleith-cli-") as tmp:
    directory = pathlib.Path(tmp)
    message = directory / "message"
    message.write_bytes(b"blind signature CLI integration test")

    def run(*args, ok=True):
        result = subprocess.run([binary, *map(str, args), "-d", tmp], capture_output=True, text=True)
        assert (result.returncode == 0) == ok, result.stdout + result.stderr
        return result

    run("keygen", "--height", 2)
    original = (directory / "signer_key.bin").read_bytes()
    run("keygen", "--height", 2, ok=False)
    assert (directory / "signer_key.bin").read_bytes() == original
    run("commit", message)
    run("sign")
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
    run("sign")
    last = (directory / "xmss_sig.bin").read_bytes()
    run("sign", ok=False)
    assert (directory / "xmss_sig.bin").read_bytes() == last
    run("params")
print("CLI round trip, invalid message, atomic state and concurrent signing passed")
