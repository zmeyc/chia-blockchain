import binascii
import io
import pkg_resources

from clvm.serialize import sexp_from_stream
from clvm_tools.clvmc import compile_clvm

from src.types.program import Program


def load_clvm(filename):
    clvm_hex = pkg_resources.resource_string(__name__, "%s.hex" % filename).decode(
        "utf8"
    )
    clvm_blob = bytes.fromhex(clvm_hex)
    return Program.from_bytes(clvm_blob)


def load_clvm1(path, search_paths=[]):
    output = f"{path}.hex"
    compile_clvm(path, output) #, search_paths=search_paths)
    h = open(output).read()
    b = binascii.unhexlify(h)
    f = io.BytesIO(b)
    s = sexp_from_stream(f, Program.to)
    return s
