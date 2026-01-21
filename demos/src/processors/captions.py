"""Caption generation in SRT and ASS formats."""

from dataclasses import dataclass
from pathlib import Path

from .tts import TTSSegment


@dataclass
class CaptionStyle:
    """Style configuration for captions."""

    font_name: str = "Inter"
    font_size: int = 48
    primary_color: str = "&HFFFFFF"  # White (ASS format: BBGGRR)
    outline_color: str = "&H000000"  # Black
    outline_width: int = 2
    shadow_depth: int = 1
    margin_v: int = 50
    alignment: int = 2  # Bottom center


@dataclass
class Caption:
    """A single caption entry."""

    index: int
    start_time: float  # seconds
    end_time: float  # seconds
    text: str


class CaptionGenerator:
    """Generates subtitle files from narration segments."""

    def __init__(self, style: CaptionStyle | None = None):
        self.style = style or CaptionStyle()

    def generate_from_segments(
        self,
        segments: list[TTSSegment],
        step_timings: dict[str, dict],
        output_path: Path,
        format: str = "srt",
    ) -> Path:
        """Generate captions from TTS segments aligned to video timings."""
        captions = self._align_captions(segments, step_timings)

        if format == "srt":
            return self._write_srt(captions, output_path)
        elif format == "ass":
            return self._write_ass(captions, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def generate_from_text(
        self,
        text_segments: list[tuple[float, float, str]],  # [(start, end, text), ...]
        output_path: Path,
        format: str = "srt",
    ) -> Path:
        """Generate captions from raw text segments with timings."""
        captions = [
            Caption(index=i + 1, start_time=start, end_time=end, text=text)
            for i, (start, end, text) in enumerate(text_segments)
        ]

        if format == "srt":
            return self._write_srt(captions, output_path)
        elif format == "ass":
            return self._write_ass(captions, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _align_captions(
        self,
        segments: list[TTSSegment],
        step_timings: dict[str, dict],
    ) -> list[Caption]:
        """Align TTS segments to video step timings."""
        captions = []
        index = 1

        for segment in segments:
            timing = step_timings.get(segment.id, {})
            start_ms = timing.get("start", 0)
            # Use TTS duration for caption length
            start_sec = start_ms / 1000.0
            end_sec = start_sec + segment.duration

            # Split long text into multiple captions
            words = segment.text.split()
            if len(words) > 10:
                # Split into chunks of ~8 words
                chunks = self._split_text(segment.text, max_words=8)
                chunk_duration = segment.duration / len(chunks)

                for i, chunk in enumerate(chunks):
                    chunk_start = start_sec + (i * chunk_duration)
                    chunk_end = chunk_start + chunk_duration
                    captions.append(
                        Caption(
                            index=index,
                            start_time=chunk_start,
                            end_time=chunk_end,
                            text=chunk,
                        )
                    )
                    index += 1
            else:
                captions.append(
                    Caption(
                        index=index,
                        start_time=start_sec,
                        end_time=end_sec,
                        text=segment.text,
                    )
                )
                index += 1

        return captions

    def _split_text(self, text: str, max_words: int = 8) -> list[str]:
        """Split text into chunks at natural boundaries."""
        words = text.split()
        chunks = []
        current_chunk = []

        for word in words:
            current_chunk.append(word)
            # Split at punctuation or max words
            if (
                len(current_chunk) >= max_words
                or word.endswith((".", ",", "!", "?", ";", ":"))
            ):
                chunks.append(" ".join(current_chunk))
                current_chunk = []

        if current_chunk:
            chunks.append(" ".join(current_chunk))

        return chunks

    def _write_srt(self, captions: list[Caption], output_path: Path) -> Path:
        """Write captions in SRT format."""
        output_path = output_path.with_suffix(".srt")
        lines = []

        for cap in captions:
            start = self._format_srt_time(cap.start_time)
            end = self._format_srt_time(cap.end_time)
            lines.append(f"{cap.index}")
            lines.append(f"{start} --> {end}")
            lines.append(cap.text)
            lines.append("")

        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    def _write_ass(self, captions: list[Caption], output_path: Path) -> Path:
        """Write captions in ASS (Advanced SubStation Alpha) format."""
        output_path = output_path.with_suffix(".ass")
        style = self.style

        header = f"""[Script Info]
Title: Demo Captions
ScriptType: v4.00+
WrapStyle: 0
ScaledBorderAndShadow: yes
YCbCr Matrix: TV.709
PlayResX: 1920
PlayResY: 1080

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Default,{style.font_name},{style.font_size},{style.primary_color},&H000000FF,{style.outline_color},&H80000000,-1,0,0,0,100,100,0,0,1,{style.outline_width},{style.shadow_depth},{style.alignment},10,10,{style.margin_v},1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""
        lines = [header.strip()]

        for cap in captions:
            start = self._format_ass_time(cap.start_time)
            end = self._format_ass_time(cap.end_time)
            # Escape special characters
            text = cap.text.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
            lines.append(f"Dialogue: 0,{start},{end},Default,,0,0,0,,{text}")

        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    def _format_srt_time(self, seconds: float) -> str:
        """Format seconds as SRT timestamp (HH:MM:SS,mmm)."""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        millis = int((seconds % 1) * 1000)
        return f"{hours:02d}:{minutes:02d}:{secs:02d},{millis:03d}"

    def _format_ass_time(self, seconds: float) -> str:
        """Format seconds as ASS timestamp (H:MM:SS.cc)."""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        centis = int((seconds % 1) * 100)
        return f"{hours}:{minutes:02d}:{secs:02d}.{centis:02d}"


def generate_captions(
    segments: list[TTSSegment],
    step_timings: dict[str, dict],
    output_path: str | Path,
    format: str = "srt",
    style: CaptionStyle | None = None,
) -> Path:
    """Convenience function for generating captions."""
    generator = CaptionGenerator(style)
    return generator.generate_from_segments(
        segments, step_timings, Path(output_path), format
    )
