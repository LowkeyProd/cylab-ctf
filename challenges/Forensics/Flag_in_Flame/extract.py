from PIL import Image
from pathlib import Path

base_dir = Path(r"C:\Users\lowkeyprod\cylab-ctf\challenges\Forensics\Flag_in_Flame")
im = Image.open(base_dir / "output.png")

# Let's crop just the characters at the tail:
# Width 896, Height 1152
w, h = im.size
crop_tail = im.crop((int(w * 0.5), h - 140, w - 20, h - 80))
crop_tail.save(base_dir / "text_tail.png")

crop_tail_large = crop_tail.resize((crop_tail.width * 3, crop_tail.height * 3), Image.Resampling.NEAREST)
crop_tail_large.save(base_dir / "text_tail_large.png")
print("Done")
