"""Kanmon.app のアイコン（1024x1024 PNG）を生成する。デザインは独自：
濃紺の角丸四角の中に、盾の輪郭と、関所の門をかたどった縦格子を置く。
使い方：python3 make_icon.py AppIcon.png（Pillow が必要）"""
import sys
from PIL import Image, ImageDraw

S = 1024
SS = 4  # スーパーサンプリング
W = S * SS


def P(x, y):
    return (int(x * W), int(y * W))


img = Image.new("RGBA", (W, W), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# 背景：角丸四角（macOS のアイコン格子に合わせ、余白 10%）
m = 0.10
r = int(0.18 * W)
d.rounded_rectangle([P(m, m), P(1 - m, 1 - m)], radius=r, fill=(18, 32, 58, 255))
d.rounded_rectangle([P(m, m), P(1 - m, 1 - m)], radius=r, outline=(64, 110, 170, 255), width=int(0.008 * W))

# 盾の輪郭
shield = [P(0.50, 0.22), P(0.74, 0.30), P(0.72, 0.56), P(0.50, 0.80), P(0.28, 0.56), P(0.26, 0.30)]
d.polygon(shield, fill=(30, 58, 98, 255), outline=(120, 190, 255, 255), width=int(0.022 * W))

# 門：上の横木と縦格子
beam_y = 0.36
d.rectangle([P(0.33, beam_y - 0.025), P(0.67, beam_y + 0.010)], fill=(240, 244, 250, 255))
for x in (0.39, 0.46, 0.54, 0.61):
    d.rectangle([P(x - 0.012, beam_y), P(x + 0.012, 0.64 - abs(x - 0.5) * 0.35)], fill=(240, 244, 250, 255))

# 中央の点（検査の目）
d.ellipse([P(0.475, 0.665), P(0.525, 0.715)], fill=(255, 196, 64, 255))

img.resize((S, S), Image.LANCZOS).save(sys.argv[1] if len(sys.argv) > 1 else "AppIcon.png")
