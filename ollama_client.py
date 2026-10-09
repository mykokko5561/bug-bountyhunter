"""
ollama_client.py
-----------------
Yerel Ollama sunucusuyla (varsayılan: http://localhost:11434) konuşan
ince istemci katmanı. Ana hedef: ağ/model hatalarının triyaj döngüsünü
KİLİTLEMEMESİ — tek bir isteğin başarısız olması tüm batch'i düşürmemeli.
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger("bugbounty.ollama_client")

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_TIMEOUT_SECONDS = 60  # Yerel LLM yavaş olabilir, sabırlı ol ama sonsuz bekleme.


@dataclass
class OllamaError(Exception):
    """Ollama ile iletişimde oluşan her türlü hatayı sarmalar."""
    message: str

    def __str__(self) -> str:
        return self.message


class OllamaClient:
    def __init__(
        self,
        model: str,
        host: str = DEFAULT_OLLAMA_HOST,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout

    def is_alive(self) -> bool:
        """Ollama servisi ayakta mı ve model yüklü mü kontrol eder."""
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            resp.raise_for_status()
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            model_available = any(self.model in m for m in models)
            if not model_available:
                logger.warning(
                    "Model '%s' Ollama'da bulunamadı. Yüklü modeller: %s",
                    self.model, models,
                )
            return model_available
        except requests.exceptions.RequestException as e:
            logger.error("Ollama servisine ulaşılamadı (%s): %s", self.host, e)
            return False

    def generate_json(self, system_prompt: str, user_prompt: str) -> Optional[dict]:
        """
        Ollama'dan yapılandırılmış (JSON) bir yanıt ister.
        Model bazen JSON'ı markdown fence içine sarabilir veya öncesine/sonrasına
        gereksiz metin ekleyebilir — bu yüzden çıktı esnek şekilde ayrıştırılır.

        Hata durumunda None döner; çağıran taraf bunu "triyaj başarısız,
        tekrar denenecek" olarak ele almalı.
        """
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "format": "json",  # Ollama'nın yerleşik JSON-mode kısıtlaması
            "stream": False,
            "options": {
                "temperature": 0.1,  # Triyaj kararında tutarlılık > yaratıcılık
            },
        }

        try:
            resp = requests.post(f"{self.host}/api/generate", json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            logger.error("Ollama zaman aşımına uğradı (model=%s, timeout=%ss)", self.model, self.timeout)
            return None
        except requests.exceptions.ConnectionError:
            logger.error("Ollama servisine bağlanılamadı: %s", self.host)
            return None
        except requests.exceptions.RequestException as e:
            logger.error("Ollama isteği başarısız: %s", e)
            return None

        try:
            raw_text = resp.json().get("response", "")
        except (json.JSONDecodeError, ValueError) as e:
            logger.error("Ollama zarfı (envelope) parse edilemedi: %s", e)
            return None

        return self._extract_json(raw_text)

    @staticmethod
    def _extract_json(text: str) -> Optional[dict]:
        """Model çıktısından JSON objesini çıkarır (markdown fence toleranslı)."""
        if not text:
            return None

        # Önce doğrudan dene.
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # ```json ... ``` fence'i temizlemeyi dene.
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fence_match:
            try:
                return json.loads(fence_match.group(1))
            except json.JSONDecodeError:
                pass

        # Son çare: metin içindeki ilk {...} bloğunu yakala.
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        logger.warning("Model çıktısından geçerli JSON çıkarılamadı: %s", text[:200])
        return None
