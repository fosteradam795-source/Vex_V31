import importlib, ctypes, os, re, sys, subprocess, tempfile

_HERE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from vex_os import build_os_bundle
from vex_sec import (
    tcp_check, banner_grab, hex_dump, hash_text, file_hash,
    file_entropy, extract_ascii_strings, ioc_scan, b64_encode, b64_decode
)

class VexBridge:
    def __init__(self):
        self.py_mods = {}
        self.libs = {}

    def py_import(self, mod_name: str, alias: str):
        self.py_mods[alias] = importlib.import_module(mod_name)

    def py_call(self, alias: str, attr_path: str, *args):
        cur = self.py_mods[alias]
        for part in attr_path.split("."):
            cur = getattr(cur, part)
        return cur(*args) if callable(cur) else cur

    def load_lib(self, path: str, alias: str):
        if os.path.exists(path):
            self.libs[alias] = ctypes.CDLL(path)

def _interp(text: str, vars_env: dict) -> str:
    for k, val in vars_env.items():
        text = text.replace("{" + k + "}", str(val))
    return text

def run_vex_source(source: str, bridge=None):
    if bridge is None:
        bridge = VexBridge()
    vars_env = {}
    outputs = []
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("py_import "):
            m = re.match(r'py_import\s+"([^"]+)"\s+as\s+(\w+)', line)
            if m:
                bridge.py_import(m.group(1), m.group(2))
            continue
        if line.startswith("c_load ") or line.startswith("rust_load "):
            m = re.match(r'(?:c_load|rust_load)\s+"([^"]+)"\s+as\s+(\w+)', line)
            if m:
                bridge.load_lib(m.group(1), m.group(2))
            continue
        if line.startswith("set."):
            body = line[4:]
            if "=" in body:
                k, v = body.split("=", 1)
                k = k.strip().rstrip(".")
                v = _interp(v.strip(), vars_env)
                try:
                    vars_env[k] = eval(v, {"__builtins__": {}}, vars_env)
                except Exception:
                    vars_env[k] = v.strip('"')
            continue
        if line.startswith("port_check."):
            parts = line[11:].split(".", 1)
            if len(parts) == 2:
                var_name, target = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                host, port_s = target.rsplit(":", 1)
                vars_env[var_name] = tcp_check(host.strip(), int(port_s.strip()))
            continue
        if line.startswith("banner."):
            parts = line[7:].split(".", 1)
            if len(parts) == 2:
                var_name, target = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                host, port_s = target.rsplit(":", 1)
                vars_env[var_name] = banner_grab(host.strip(), int(port_s.strip()))
            continue
        if line.startswith("hexdump."):
            parts = line[8:].split(".", 1)
            if len(parts) == 2:
                var_name, txt = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                vars_env[var_name] = hex_dump(txt)
            continue
        if line.startswith("hash."):
            parts = line[5:].split(".", 1)
            if len(parts) == 2:
                var_name, spec = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                algo, txt = spec.split(":", 1)
                vars_env[var_name] = hash_text(txt, algo.strip())
            continue
        if line.startswith("file_hash."):
            parts = line[10:].split(".", 1)
            if len(parts) == 2:
                var_name, spec = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                if ":" in spec and not os.path.exists(spec):
                    algo, fpath = spec.split(":", 1)
                else:
                    algo, fpath = "sha256", spec
                vars_env[var_name] = file_hash(fpath.strip(), algo.strip())
            continue
        if line.startswith("entropy."):
            parts = line[8:].split(".", 1)
            if len(parts) == 2:
                var_name, fpath = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                vars_env[var_name] = file_entropy(fpath.strip())
            continue
        if line.startswith("strings."):
            parts = line[8:].split(".", 1)
            if len(parts) == 2:
                var_name, fpath = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                vars_env[var_name] = extract_ascii_strings(fpath.strip())
            continue
        if line.startswith("ioc_scan."):
            parts = line[9:].split(".", 1)
            if len(parts) == 2:
                var_name, txt = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                vars_env[var_name] = ioc_scan(txt)
            continue
        if line.startswith("b64_enc."):
            parts = line[8:].split(".", 1)
            if len(parts) == 2:
                var_name, txt = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                vars_env[var_name] = b64_encode(txt)
            continue
        if line.startswith("b64_dec."):
            parts = line[8:].split(".", 1)
            if len(parts) == 2:
                var_name, txt = parts[0].strip(), _interp(parts[1].strip(), vars_env)
                vars_env[var_name] = b64_decode(txt)
            continue
        if line.startswith("os_compile."):
            out_folder = line[11:].strip() or "os_build"
            bundle = build_os_bundle(source, out_folder)
            outputs.append(f"[OS Build Ready] Generated {bundle['boot_s']}, {bundle['kernel_c']}, {bundle['linker_ld']}")
            continue
        if line.startswith("write."):
            msg = _interp(line[6:], vars_env)
            outputs.append(msg)
    return "\n".join(outputs)

def execute_by_language(lang: str, source: str, bridge=None) -> str:
    """Run code according to selected coding language in Vex V31."""
    lang_norm = (lang or "Vex (.vx)").strip()

    if lang_norm.startswith("Vex"):
        return run_vex_source(source, bridge)

    if lang_norm == "Python":
        local_ns = {"__name__": "__vex_py__"}
        buf = []
        import io, contextlib
        out_io = io.StringIO()
        try:
            with contextlib.redirect_stdout(out_io):
                exec(source, local_ns)
            res = out_io.getvalue().strip()
            return res if res else "[Python] Executed cleanly (no stdout)."
        except Exception as exc:
            return f"[Python Error] {exc}"

    if lang_norm == "C++":
        tmp_dir = tempfile.mkdtemp(prefix="vex_cpp_")
        src_p = os.path.join(tmp_dir, "main.cpp")
        exe_p = os.path.join(tmp_dir, "main.exe")
        with open(src_p, "w", encoding="utf-8") as f:
            f.write(source)
        comp = subprocess.run(["g++", "-O2", "-std=c++17", src_p, "-o", exe_p], capture_output=True, text=True)
        if comp.returncode != 0:
            return f"[C++ Compile Error]\n{comp.stderr or comp.stdout}"
        run = subprocess.run([exe_p], capture_output=True, text=True)
        return (run.stdout or run.stderr or "[C++] Done.").strip()

    if lang_norm == "C":
        tmp_dir = tempfile.mkdtemp(prefix="vex_c_")
        src_p = os.path.join(tmp_dir, "main.c")
        exe_p = os.path.join(tmp_dir, "main.exe")
        with open(src_p, "w", encoding="utf-8") as f:
            f.write(source)
        comp = subprocess.run(["gcc", "-O2", src_p, "-o", exe_p], capture_output=True, text=True)
        if comp.returncode != 0:
            return f"[C Compile Error]\n{comp.stderr or comp.stdout}"
        run = subprocess.run([exe_p], capture_output=True, text=True)
        return (run.stdout or run.stderr or "[C] Done.").strip()

    if lang_norm == "Rust":
        tmp_dir = tempfile.mkdtemp(prefix="vex_rs_")
        src_p = os.path.join(tmp_dir, "main.rs")
        exe_p = os.path.join(tmp_dir, "main.exe")
        with open(src_p, "w", encoding="utf-8") as f:
            f.write(source)
        comp = subprocess.run(["rustc", "-O", src_p, "-o", exe_p], capture_output=True, text=True)
        if comp.returncode != 0:
            return f"[Rust Compile Error]\n{comp.stderr or comp.stdout}"
        run = subprocess.run([exe_p], capture_output=True, text=True)
        return (run.stdout or run.stderr or "[Rust] Done.").strip()

    if lang_norm == "x86 Assembly":
        bundle = build_os_bundle(f"asm.{source.strip()}\nhalt." if source.strip() and "\n" not in source else source, "os_build")
        return f"[x86 Assembly] Emitted Multiboot stub + kernel into {bundle['boot_s']} and {bundle['kernel_c']}."

    return run_vex_source(source, bridge)
