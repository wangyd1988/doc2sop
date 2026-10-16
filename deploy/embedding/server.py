"""Minimal OpenAI-compatible embedding server (CPU only).

Runs on its own host so the 2 GB application box never loads a model. FastEmbed
keeps this to an ONNX runtime instead of a full PyTorch install, which is the
difference between ~800 MB and several gigabytes of RAM.
"""
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastembed import TextEmbedding
from fastembed.common.model_description import ModelSource, PoolingType

# Public model name clients must send, and the ONNX export actually loaded.
MODEL_NAME = os.environ.get("MODEL_NAME", "BAAI/bge-base-zh-v1.5")
ONNX_REPO = os.environ.get("ONNX_REPO", "Xenova/bge-base-zh-v1.5")
MODEL_DIM = int(os.environ.get("MODEL_DIM", "768"))
# fastembed 有自己的缓存目录，不认 HF_HOME。不显式指定的话模型会落在
# /tmp/fastembed_cache——容器一重建就得重新下载，离线环境直接失败。
CACHE_DIR = os.environ.get("MODEL_CACHE_DIR", "/models")
MAX_BODY_BYTES = 65536
MAX_TEXTS = 16

logging.basicConfig(level=logging.INFO)

if ONNX_REPO not in {m["model"] for m in TextEmbedding.list_supported_models()}:
    TextEmbedding.add_custom_model(
        model=ONNX_REPO, pooling=PoolingType.CLS, normalization=True,
        sources=ModelSource(hf=ONNX_REPO), dim=MODEL_DIM, model_file="onnx/model.onnx")
model = TextEmbedding(model_name=ONNX_REPO, threads=2, cache_dir=CACHE_DIR)
logging.info("模型就绪：%s（缓存目录 %s）", MODEL_NAME, CACHE_DIR)


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
        if self.path != "/v1/embeddings":
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

        texts = request.get("input") if isinstance(request, dict) else None
        if isinstance(texts, str):
            texts = [texts]
        if (not isinstance(texts, list) or not 1 <= len(texts) <= MAX_TEXTS
                or any(not isinstance(text, str) or not text.strip() for text in texts)):
            self.respond(400, {"error": {"message": f"input must contain 1-{MAX_TEXTS} nonempty strings"}})
            return
        if request.get("model") != MODEL_NAME:
            self.respond(400, {"error": {"message": "Unsupported model"}})
            return

        try:
            vectors = [vector.tolist() for vector in model.embed(texts, batch_size=8)]
        except Exception:
            logging.exception("Embedding inference failed")
            self.respond(500, {"error": {"message": "Embedding inference failed"}})
            return

        self.respond(200, {
            "object": "list",
            "data": [{"object": "embedding", "index": i, "embedding": vector}
                     for i, vector in enumerate(vectors)],
            "model": MODEL_NAME,
            "usage": {"prompt_tokens": 0, "total_tokens": 0},
        })

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
