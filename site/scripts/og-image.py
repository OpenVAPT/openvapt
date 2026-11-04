# Draws the 1200x630 Open Graph image (static/assets/og-image.png) from the
# site's own design tokens (Ant Design blue-6 #1677ff, blue-7 #0958d9, blue-1
# #e6f4ff, ink) and the self-hosted IBM Plex fonts. It is a drawing, not an AI
# image. The PNG is committed; rerun only when the wordmark or tagline changes:
#   python3 scripts/og-image.py <folder with IBMPlex*.ttf> static/assets/og-image.png
# (convert the vendored woff2 files to ttf with fontTools first). Needs Pillow.
import sys
from PIL import Image, ImageDraw, ImageFont
fonts, out = sys.argv[1], sys.argv[2]
W, H = 1200, 630
im = Image.new("RGB", (W, H), "#ffffff")
d = ImageDraw.Draw(im)
INK, INK2, INK3 = (31, 31, 31), (89, 89, 89), (110, 110, 110)
BLUE6, BLUE7, BLUE1, BLUE2, LINE = "#1677ff", "#0958d9", "#e6f4ff", "#bae0ff", "#f0f0f0"
F = lambda n, s: ImageFont.truetype(f"{fonts}/{n}.ttf", s)
# Left accent bar and a soft layer band at the bottom
d.rectangle([0, 0, 14, H], fill=BLUE6)
d.rectangle([0, H - 96, W, H], fill="#f4f4f4")
d.line([0, H - 96, W, H - 96], fill=LINE, width=2)
# Icon: rounded square, ring and crosshair ticks, as in assets/icon.svg
x, y, s = 72, 64, 88
d.rounded_rectangle([x, y, x + s, y + s], radius=19, fill=BLUE6)
cx, cy = x + s / 2, y + s / 2
d.ellipse([cx - 23, cy - 23, cx + 23, cy + 23], outline="#ffffff", width=8)
for a, b in [((cx, cy - 23 - 12), (cx, cy - 23 - 1)), ((cx, cy + 23 + 1), (cx, cy + 23 + 12)),
             ((cx - 23 - 12, cy), (cx - 23 - 1, cy)), ((cx + 23 + 1, cy), (cx + 23 + 12, cy))]:
    d.line([a, b], fill="#ffffff", width=7)
d.text((x + s + 28, y + 6), "OpenVAPT", font=F("IBMPlexSans-SemiBold", 66), fill=INK)
# Tag chip row (Ant Tag look)
chips = ["Academic", "Non-Commercial", "Source-Available", "Free"]
cxp, cyp = 72, 196
small = F("IBMPlexSans-Medium", 22)
for c in chips:
    w = d.textlength(c, font=small)
    d.rounded_rectangle([cxp, cyp, cxp + w + 28, cyp + 40], radius=6, fill=BLUE1, outline=BLUE2, width=2)
    d.text((cxp + 14, cyp + 7), c, font=small, fill=BLUE7)
    cxp += w + 28 + 12
# Headline and tagline
d.text((72, 268), "See Exactly How a Vulnerability", font=F("IBMPlexSans-SemiBold", 54), fill=INK)
d.text((72, 334), "Assessment Tool Works", font=F("IBMPlexSans-SemiBold", 54), fill=INK)
body = F("IBMPlexSans-Regular", 27)
d.text((72, 420), "Read every line, then run it on your own Linux server. Built by", font=body, fill=INK2)
d.text((72, 458), "AI Cybersecurity Engineers. Free for your own use, 100% at your own risk.", font=body, fill=INK2)
mono = F("IBMPlexMono-Regular", 24)
d.text((72, H - 62), "openvapt.com", font=mono, fill=INK2)
right = "Read-only checks for the Linux machine it runs on"
d.text((W - 72 - d.textlength(right, font=F("IBMPlexSans-Regular", 22)), H - 60), right, font=F("IBMPlexSans-Regular", 22), fill=INK3)
im.save(out, optimize=True)
print(out)
