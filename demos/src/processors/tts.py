"""OpenAI TTS integration with caching."""

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass
class TTSConfig:
    """Configuration for TTS generation."""

    voice: str = "alloy"
    model: str = "tts-1-hd"
    speed: float = 1.0
    response_format: str = "mp3"


@dataclass
class TTSSegment:
    """A single TTS segment with its audio file."""

    id: str
    text: str
    audio_path: Path
    duration: float  # seconds


class TTSProcessor:
    """Generates TTS audio using OpenAI's API with local caching."""

    VOICES = ["alloy", "echo", "fable", "onyx", "nova", "shimmer"]

    def __init__(self, cache_dir: Path, api_key: str | None = None):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not set")

    def generate_narration(
        self,
        segments: list[tuple[str, str]],  # [(id, text), ...]
        config: TTSConfig | None = None,
    ) -> list[TTSSegment]:
        """Generate TTS audio for multiple narration segments."""
        config = config or TTSConfig()
        results = []

        for segment_id, text in segments:
            if not text.strip():
                continue

            audio_path = self._get_or_generate(segment_id, text, config)
            duration = self._get_audio_duration(audio_path)

            results.append(
                TTSSegment(
                    id=segment_id,
                    text=text,
                    audio_path=audio_path,
                    duration=duration,
                )
            )

        return results

    def generate_single(
        self, text: str, output_path: Path, config: TTSConfig | None = None
    ) -> TTSSegment:
        """Generate TTS for a single text segment."""
        config = config or TTSConfig()
        segment_id = self._hash_text(text)

        # Check cache first
        cached = self._get_cached(segment_id, config)
        if cached and cached.exists():
            # Copy to output path
            import shutil
            shutil.copy2(cached, output_path)
        else:
            # Generate new
            self._call_api(text, output_path, config)
            # Cache it
            self._cache_audio(segment_id, output_path, config)

        duration = self._get_audio_duration(output_path)
        return TTSSegment(
            id=segment_id,
            text=text,
            audio_path=output_path,
            duration=duration,
        )

    def _get_or_generate(
        self, segment_id: str, text: str, config: TTSConfig
    ) -> Path:
        """Get from cache or generate new audio."""
        cache_key = self._make_cache_key(segment_id, text, config)
        cached_path = self.cache_dir / f"{cache_key}.{config.response_format}"

        if cached_path.exists():
            return cached_path

        # Generate new audio
        self._call_api(text, cached_path, config)
        return cached_path

    def _call_api(self, text: str, output_path: Path, config: TTSConfig) -> None:
        """Call OpenAI TTS API."""
        with httpx.Client(timeout=60.0) as client:
            response = client.post(
                "https://api.openai.com/v1/audio/speech",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": config.model,
                    "input": text,
                    "voice": config.voice,
                    "speed": config.speed,
                    "response_format": config.response_format,
                },
            )
            response.raise_for_status()

            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(response.content)

    def _get_cached(self, segment_id: str, config: TTSConfig) -> Path | None:
        """Check if audio is already cached."""
        pattern = f"{segment_id}_*.{config.response_format}"
        matches = list(self.cache_dir.glob(pattern))
        return matches[0] if matches else None

    def _cache_audio(
        self, segment_id: str, audio_path: Path, config: TTSConfig
    ) -> None:
        """Cache audio file."""
        import shutil
        cache_key = self._make_cache_key(segment_id, "", config)
        cached_path = self.cache_dir / f"{cache_key}.{config.response_format}"
        if not cached_path.exists():
            shutil.copy2(audio_path, cached_path)

    def _make_cache_key(
        self, segment_id: str, text: str, config: TTSConfig
    ) -> str:
        """Create a cache key for the segment."""
        content = f"{segment_id}:{text}:{config.voice}:{config.speed}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _hash_text(self, text: str) -> str:
        """Create a short hash of text for identification."""
        return hashlib.sha256(text.encode()).hexdigest()[:12]

    def _get_audio_duration(self, audio_path: Path) -> float:
        """Get duration of audio file using ffprobe."""
        import subprocess

        try:
            result = subprocess.run(
                [
                    "ffprobe",
                    "-v", "error",
                    "-show_entries", "format=duration",
                    "-of", "default=noprint_wrappers=1:nokey=1",
                    str(audio_path),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return float(result.stdout.strip())
        except Exception:
            # Fallback: estimate based on text length (150 wpm average)
            return 0.0


def generate_narration(
    segments: list[tuple[str, str]],
    cache_dir: str | Path,
    config: TTSConfig | None = None,
) -> list[TTSSegment]:
    """Convenience function for generating narration."""
    processor = TTSProcessor(Path(cache_dir))
    return processor.generate_narration(segments, config)
