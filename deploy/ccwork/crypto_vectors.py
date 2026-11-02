#!/usr/bin/env python3
"""厂商加密程序的对照数据（设计「不开源的加密程序」方案乙）：正式运行不用厂商程序，开发时在断网的隔离环境里
跑它一次，拿它的输出核对我们自己的实现（ccwork_bridge.encrypt / decrypt）。官方发新版程序时照样再跑一遍。

    python3 crypto_vectors.py requests IN_DIR
        生成请求：随机密钥、随机明文（固定种子，不碰任何真实凭据），每个请求一个 NNNN.json，另写 cases.json
    （在隔离环境里对每个请求跑一次厂商程序：<程序> --request-stdin-json < NNNN.json > NNNN.out 2> NNNN.err，
     退出码写进 NNNN.rc）
    python3 crypto_vectors.py collect IN_DIR OUT_DIR FIXTURE --sha256 … --command "…"
        汇总成测试数据（tests/fixtures/ccwork_crypto_vectors.json）

请求的写法是厂商程序的 JSON 协议：version、op（encrypt / decrypt）、alg（aes-ecb / sm4-cbc）、input_encoding、
output_encoding、key（base64）、key_encoding、data、transport_format。
"""
import argparse
import base64
import json
import random
import string
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ccwork_bridge as bridge  # noqa: E402

SEED = 20261102
ALGS = {"aes": "aes-ecb", "sm4": "sm4-cbc"}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field(number, data: bytes):
    return _varint(number << 3 | 2) + _varint(len(data)) + data


def plaintexts(rng):
    """明文：空、ASCII 各种长度（块边界前后）、中文、带 0x80–0xff 的原始字节、一条 Text 消息（长度字段是两字节 varint）。"""
    def ascii_text(n):
        return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n)).encode()

    def raw(n):
        return bytes(rng.randrange(256) for _ in range(n))

    question = "知识库里怎么申请 VPN 权限？要走哪个流程，谁来审批，多久能开通？还有外包同事能不能申请？谢谢" * 2
    message = _field(1, question.encode()) + _field(2, b"98765")
    return {"empty": b"", "a1": ascii_text(1), "a15": ascii_text(15), "a16": ascii_text(16), "a17": ascii_text(17),
            "zh": "云上协同里 @doc2sop 提问：kb-app 内存高怎么办？".encode(), "bin127": raw(127), "bin128": raw(128),
            "bin200": raw(200), "pb": message}


def keys(rng):
    def text_key(n):
        return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n)).encode()

    return {"aes": {"t16": text_key(16), "t32": text_key(32), "b16": bytes(rng.randrange(256) for _ in range(16))},
            "sm4": {"t16": text_key(16), "b16": bytes(rng.randrange(256) for _ in range(16))}}


def request(alg, op, input_encoding, output_encoding, key: bytes, data: str):
    return {"version": 1, "op": op, "alg": ALGS[alg], "input_encoding": input_encoding,
            "output_encoding": output_encoding, "key": b64(key), "key_encoding": "base64", "data": data,
            "transport_format": "json"}


def build_cases():
    rng = random.Random(SEED)
    texts, keyring = plaintexts(rng), keys(rng)
    cases = []

    def add(name, alg, key_name, key, plain, req):
        cases.append({"id": f"{len(cases) + 1:04d}", "name": name, "alg": alg, "key_name": key_name,
                      "plain": b64(plain) if plain is not None else None, "request": req})

    for alg, ring in keyring.items():
        for key_name, key in ring.items():
            for text_name, plain in texts.items():
                cipher = bridge.encrypt(alg, plain, key)
                add(f"encrypt raw {text_name}", alg, key_name, key, plain,
                    request(alg, "encrypt", "raw_base64", "raw_base64", key, b64(plain)))
                # 消息正文的解密路径（SDK 用 utf8 输出）；再看 raw_base64 输出能不能原样拿回字节
                add(f"decrypt raw->utf8 {text_name}", alg, key_name, key, plain,
                    request(alg, "decrypt", "raw_base64", "utf8", key, b64(cipher)))
                add(f"decrypt raw->raw {text_name}", alg, key_name, key, plain,
                    request(alg, "decrypt", "raw_base64", "raw_base64", key, b64(cipher)))
                try:
                    text = plain.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if text_name == "pb":
                    continue
                # 摘要的路径：明文进、base64 出；base64 进、utf8 出
                add(f"encrypt plain {text_name}", alg, key_name, key, plain,
                    request(alg, "encrypt", "plain", "base64", key, text))
                add(f"decrypt base64->utf8 {text_name}", alg, key_name, key, plain,
                    request(alg, "decrypt", "base64", "utf8", key, b64(cipher)))
        long_plain = bytes(rng.randrange(256) for _ in range(1000))
        key = next(iter(ring.values()))
        add("encrypt raw bin1000", alg, "first", key, long_plain,
            request(alg, "encrypt", "raw_base64", "raw_base64", key, b64(long_plain)))
        add("decrypt raw->raw bin1000", alg, "first", key, long_plain,
            request(alg, "decrypt", "raw_base64", "raw_base64", key, b64(bridge.encrypt(alg, long_plain, key))))
        # 出错的样子：密文不是块的整数倍、填充不对、密钥长度不对
        add("decrypt bad length", alg, "first", key, None,
            request(alg, "decrypt", "raw_base64", "raw_base64", key, b64(b"x" * 20)))
        add("decrypt bad padding", alg, "first", key, None,
            request(alg, "decrypt", "raw_base64", "raw_base64", key, b64(bytes(rng.randrange(256) for _ in range(32)))))
        add("encrypt bad key", alg, "short", b"0123456789", b"abc",
            request(alg, "encrypt", "raw_base64", "raw_base64", b"0123456789", b64(b"abc")))
    return cases


def write_requests(folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    cases = build_cases()
    for case in cases:
        (folder / f"{case['id']}.json").write_text(json.dumps(case["request"], ensure_ascii=False), encoding="utf-8")
    (folder / "cases.json").write_text(json.dumps(cases, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {len(cases)} requests to {folder}")


def collect(in_dir, out_dir, fixture, sha256, command, run_at):
    in_dir, out_dir = Path(in_dir), Path(out_dir)
    cases = json.loads((in_dir / "cases.json").read_text(encoding="utf-8"))
    rows = []
    for case in cases:
        raw = (out_dir / f"{case['id']}.out").read_bytes()
        try:
            response = json.loads(raw)
        except ValueError:
            response = {"unparsed": raw.decode("utf-8", "replace")}
        rows.append({**case, "rc": int((out_dir / f"{case['id']}.rc").read_text().strip() or "-1"),
                     "stderr": (out_dir / f"{case['id']}.err").read_text(encoding="utf-8", errors="replace")[:500],
                     "response": response})
    data = {"about": "厂商加密程序在 A 上用 gVisor 断网跑一次得到的对照数据；输入全是固定种子生成的随机密钥和明文，"
                     "不含任何真实凭据。见 deploy/ccwork/crypto_vectors.py",
            "vendor": {"file": "ccwork-crypto-linux-amd64", "sha256": sha256,
                       "sdk": "ccwork-sdk/ccwork-chat-sdk-go 2cf4953（v1.0.0）", "run_at": run_at, "command": command},
            "cases": rows}
    Path(fixture).write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} cases to {fixture}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    req = sub.add_parser("requests")
    req.add_argument("in_dir")
    col = sub.add_parser("collect")
    col.add_argument("in_dir")
    col.add_argument("out_dir")
    col.add_argument("fixture")
    col.add_argument("--sha256", required=True)
    col.add_argument("--command", dest="run_command", required=True)
    col.add_argument("--run-at", required=True)
    args = parser.parse_args(argv)
    if args.command == "requests":
        write_requests(args.in_dir)
    else:
        collect(args.in_dir, args.out_dir, args.fixture, args.sha256, args.run_command, args.run_at)
    return 0


if __name__ == "__main__":
    sys.exit(main())
