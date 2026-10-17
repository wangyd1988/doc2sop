"""Minimal Infinity/Cohere-compatible rerank server (CPU only).

Sits next to the embedding server on the same small host. A cross-encoder scores
(query, passage) pairs jointly, which is what a bi-encoder vector search cannot
do; it is run only on the ~30 candidates retrieval already found, so CPU is fine.

Request  POST /rerank  {"query": str, "documents": [str], "top_n": int, "return_documents": bool}
Response {"results": [{"index": i, "relevance_score": s, "document": {"text": ...}?}], "model": ...}
"""
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import numpy as np
import onnxruntime as ort
from huggingface_hub import snapshot_download
from tokenizers import Tokenizer

MODEL_NAME = os.environ.get("MODEL_NAME", "BAAI/bge-reranker-base")
# fastembed 自带的 bge-reranker-base 是 fp32 ONNX（1.04 GB），这台 2 GB 机器放不下；
# 用同一仓库的 int8 量化导出，约 280 MB，中文效果差别很小。
# 不经 fastembed 而直接用 onnxruntime：可以关掉内存 arena、单线程，常驻内存小一半。
ONNX_REPO = os.environ.get("ONNX_REPO", "Xenova/bge-reranker-base")
ONNX_FILE = os.environ.get("ONNX_FILE", "onnx/model_quantized.onnx")
CACHE_DIR = os.environ.get("MODEL_CACHE_DIR", "/models")
MAX_BODY_BYTES = 256 * 1024
MAX_DOCS = 64
# 交叉编码器的耗时基本与 token 数成正比。判断「这段和问题相关不相关」看前 300 来个 token 足够，
# 全文 512 要慢一倍。可用环境变量调。
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "256"))

logging.basicConfig(level=logging.INFO)

local = snapshot_download(ONNX_REPO, cache_dir=CACHE_DIR,
                          allow_patterns=[ONNX_FILE, "tokenizer.json", "tokenizer_config.json",
                                          "special_tokens_map.json", "config.json"])
tokenizer = Tokenizer.from_file(os.path.join(local, "tokenizer.json"))
tokenizer.enable_truncation(MAX_TOKENS)
tokenizer.enable_padding(pad_id=tokenizer.token_to_id("<pad>") or 1, pad_token="<pad>")
opts = ort.SessionOptions()
opts.enable_cpu_mem_arena = False
opts.enable_mem_pattern = False
# 预打包会把量化权重再复制一份成内核友好格式；关掉省 ~200 MB，速度影响可忽略
opts.add_session_config_entry("session.disable_prepacking", "1")
opts.intra_op_num_threads = int(os.environ.get("THREADS", "2"))
opts.inter_op_num_threads = 1
# 加载时的图优化会临时复制整张图，在小内存机器上容易被 OOM 杀；量化模型本身已是推理友好的，关掉即可
opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_DISABLE_ALL
session = ort.InferenceSession(os.path.join(local, ONNX_FILE), opts, providers=["CPUExecutionProvider"])
INPUTS = {i.name for i in session.get_inputs()}
logging.info("重排模型就绪：%s（%s/%s，缓存目录 %s）", MODEL_NAME, ONNX_REPO, ONNX_FILE, CACHE_DIR)


def score_pairs(query: str, docs: list, batch_size: int = 8) -> list:
    out = []
    for start in range(0, len(docs), batch_size):
        enc = tokenizer.encode_batch([(query, d) for d in docs[start:start + batch_size]])
        feed = {"input_ids": np.array([e.ids for e in enc], dtype=np.int64),
                "attention_mask": np.array([e.attention_mask for e in enc], dtype=np.int64)}
        if "token_type_ids" in INPUTS:
            feed["token_type_ids"] = np.array([e.type_ids for e in enc], dtype=np.int64)
        logits = session.run(None, feed)[0]
        out.extend(float(x) for x in logits.reshape(-1))
    return out


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.respond(200, {"status": "ok", "model": MODEL_NAME})
        else:
            self.respond(404, {"error": {"message": "Not found"}})

    def do_POST(self):
        if self.path not in ("/rerank", "/v1/rerank"):
            self.respond(404, {"error": {"message": "Not found"}})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.respond(400, {"error": {"message": "Invalid Content-Length"}})
            return
        if not 0 < length <= MAX_BODY_BYTES:
            self.respond(413, {"error": {"message": "Request body too large or empty"}})
            return
        try:
            request = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self.respond(400, {"error": {"message": "Invalid JSON"}})
            return

        query = request.get("query") if isinstance(request, dict) else None
        docs = request.get("documents") if isinstance(request, dict) else None
        if isinstance(docs, list):
            docs = [d.get("text", "") if isinstance(d, dict) else d for d in docs]
        if (not isinstance(query, str) or not query.strip() or not isinstance(docs, list)
                or not 1 <= len(docs) <= MAX_DOCS or any(not isinstance(d, str) for d in docs)):
            self.respond(400, {"error": {"message": f"query and 1-{MAX_DOCS} documents required"}})
            return
        top_n = request.get("top_n") or len(docs)
        try:
            top_n = max(1, min(int(top_n), len(docs)))
        except (TypeError, ValueError):
            top_n = len(docs)

        try:
            scores = score_pairs(query, [d or " " for d in docs])
        except Exception:
            logging.exception("Rerank inference failed")
            self.respond(500, {"error": {"message": "Rerank inference failed"}})
            return

        order = sorted(range(len(docs)), key=lambda i: -float(scores[i]))[:top_n]
        results = [{"index": i, "relevance_score": float(scores[i])} for i in order]
        if request.get("return_documents"):
            for r in results:
                r["document"] = {"text": docs[r["index"]]}
        self.respond(200, {"results": results, "model": MODEL_NAME,
                           "usage": {"total_tokens": 0}, "meta": {"api_version": {"version": "1"}}})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
