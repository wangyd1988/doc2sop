"""Multimodal OCR for images embedded in documents.

Screenshots and diagrams carry a lot of the information in real notes, so each
image is sent to a vision model and the result is spliced back into the position
it occupied in the text.
"""
import base64
import hashlib
import io
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from PIL import Image
from langchain_core.messages import HumanMessage

from app.clients import vision_llms
from app.config import (MAX_IMAGES_PER_FILE, MAX_IMAGE_SIDE, MIN_IMAGE_AREA, MIN_IMAGE_SIDE,
                        VISION_CACHE_PATH, VISION_MODELS, VISION_WORKERS, log, why)

VISION_PROMPT = """这是知识库文档中的一张图片。请：
1. 按原有阅读顺序完整提取图中的所有文字（表格按行输出，单元格用 | 分隔）；
2. 如果是截图、图表、流程图、架构图或照片，再用 1-3 句中文说明它展示的关键信息（如数据趋势、流程步骤、界面位置）。
直接输出内容，不要寒暄。如果图片只是装饰、图标、logo 或空白，没有有用信息，只输出：无"""

_cache_lock = threading.Lock()
try:
    _cache = json.loads(VISION_CACHE_PATH.read_text(encoding="utf-8"))
except (FileNotFoundError, ValueError):
    _cache = {}


def describe_image(jpeg: bytes) -> str:
    """Return the image's text ('' if uninformative). Raises if every model fails."""
    url = "data:image/jpeg;base64," + base64.b64encode(jpeg).decode()
    message = HumanMessage(content=[{"type": "text", "text": VISION_PROMPT},
                                    {"type": "image_url", "image_url": {"url": url}}])
    last_error = None
    for name, model in zip(VISION_MODELS, vision_llms):
        try:
            text = (model.invoke([message]).content or "").strip()
        except Exception as exc:
            log.warning("vision model %s failed: %s", name, exc.__class__.__name__)
            last_error = exc
            continue
        return "" if text.rstrip("。.").strip() in ("", "无") else text
    raise RuntimeError(f"所有图片识别模型均失败：{why(last_error) if last_error else '无可用模型'}")


class ImageCollector:
    """Collects images during extraction, leaving placeholders later replaced by descriptions."""

    def __init__(self):
        self.images = {}        # token -> (cache_key, jpeg bytes)
        self.results = {}       # token -> text
        self.seen = {}          # cache_key -> token
        self.skipped = 0
        self.failed = 0
        self.on_progress = None  # callable(done, total)，后台入库用来汇报进度

    def add(self, source) -> str:
        """Accept raw bytes or a PIL image; return a placeholder token ('' if skipped)."""
        try:
            raw = source if isinstance(source, bytes) else None
            image = Image.open(io.BytesIO(raw)) if raw is not None else source
            image.load()
            width, height = image.size
            # Icons, bullets and logos carry no text worth a model call.
            if min(width, height) < MIN_IMAGE_SIDE or width * height < MIN_IMAGE_AREA:
                return ""
            if raw is None:
                raw = image.tobytes()
            key = hashlib.sha256(raw).hexdigest()
            if key in self.seen:
                return self.seen[key]
            if len(self.images) >= MAX_IMAGES_PER_FILE:
                self.skipped += 1
                return ""
            if getattr(image, "is_animated", False):
                image.seek(0)
            if image.mode not in ("RGB", "L"):
                # Flatten transparency onto white so JPEG does not turn it black.
                rgba = image.convert("RGBA")
                image = Image.new("RGB", rgba.size, "white")
                image.paste(rgba, mask=rgba.split()[3])
            image.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
            buffer = io.BytesIO()
            image.convert("RGB").save(buffer, "JPEG", quality=85)
        except Exception as exc:
            log.info("skip unreadable image: %s", exc.__class__.__name__)
            self.skipped += 1
            return ""
        token = f"\x00IMG{len(self.images)}\x00"
        self.images[token] = (key, buffer.getvalue())
        self.seen[key] = token
        return token

    def describe_all(self):
        """Recognise every collected image, reusing cached results across uploads."""
        def work(item):
            token, (key, jpeg) = item
            with _cache_lock:
                if key in _cache:
                    return token, _cache[key]
            try:
                text = describe_image(jpeg)
            except Exception:
                return token, None
            with _cache_lock:
                _cache[key] = text
            return token, text

        with ThreadPoolExecutor(max_workers=VISION_WORKERS) as pool:
            done = 0
            for token, text in pool.map(work, self.images.items()):
                if text is None:
                    self.failed += 1
                    text = ""
                self.results[token] = text
                done += 1
                if self.on_progress:
                    self.on_progress(done, len(self.images))
        self._save_cache()

    def _save_cache(self):
        with _cache_lock:
            temp = VISION_CACHE_PATH.with_suffix(".tmp")
            temp.write_text(json.dumps(_cache, ensure_ascii=False), encoding="utf-8")
            os.replace(temp, VISION_CACHE_PATH)

    def fill(self, text: str) -> str:
        """Swap placeholders for the recognised content, in place."""
        for token, description in self.results.items():
            text = text.replace(token, f"\n〔图片内容〕\n{description}\n" if description else "")
        return text

    def stats(self):
        described = sum(1 for text in self.results.values() if text)
        return {"found": len(self.images), "described": described,
                "failed": self.failed, "skipped": self.skipped}
