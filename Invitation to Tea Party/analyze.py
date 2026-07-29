from collections import Counter, defaultdict
from hashlib import md5, sha256
from pathlib import Path

from PIL import Image, ImageStat


ROOT = Path("alice_tea_table_cipher")


def average_hash(image: Image.Image, size: int = 16) -> str:
    pixels = list(image.convert("L").resize((size, size)).getdata())
    average = sum(pixels) / len(pixels)
    bits = sum((pixel >= average) << index for index, pixel in enumerate(pixels))
    return f"{bits:0{size * size // 4}x}"


outliers = []
dimensions = Counter()
for path in ROOT.glob("*/*.jpg"):
    with Image.open(path) as image:
        dimensions[image.size] += 1
        if image.size != (683, 1052):
            continue
        stats = ImageStat.Stat(image)
        data = path.read_bytes()
        outliers.append(
            {
                "char": path.parent.name,
                "name": path.stem,
                "size": path.stat().st_size,
                "mtime": path.stat().st_mtime_ns,
                "md5": md5(data).hexdigest(),
                "sha256": sha256(data).hexdigest(),
                "mean": sum(stats.mean) / 3,
                "stddev": sum(stats.stddev) / 3,
                "ahash": average_hash(image),
            }
        )

print("dimensions:", dimensions)
print("outlier count:", len(outliers))
for key in ("name", "size", "mtime", "md5", "sha256", "mean", "stddev", "ahash"):
    ordered = sorted(outliers, key=lambda row: (row[key], row["name"]))
    print(f"{key:>8}: {''.join(row['char'] for row in ordered)}")

print("\nOutliers ordered by size:")
for index, row in enumerate(sorted(outliers, key=lambda item: item["size"])):
    print(
        f"{index:02d} {row['char']} {row['name']} {row['size']:6d} "
        f"mean={row['mean']:7.3f} stddev={row['stddev']:7.3f} "
        f"ahash={row['ahash'][:16]}"
    )
