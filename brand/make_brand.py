# Builds every HidraNet logo and icon from the one master image.
import sys, os
from PIL import Image, ImageDraw, ImageFilter

SRC = sys.argv[1]
OUT = sys.argv[2]
os.makedirs(OUT, exist_ok=True)

src = Image.open(SRC).convert('RGB')
w, h = src.size
px = src.load()

# Transparent version: the background is pure black, the fill is a solid
# green with a darker bevel. Alpha comes from how far a pixel is from black
# (anti-aliased edges become partly transparent), and the colour is divided
# back out so an edge pixel keeps the logo's green instead of going murky.
FULL = 100  # green channel at and above which a pixel is fully opaque
logo = Image.new('RGBA', (w, h), (0, 0, 0, 0))
lp = logo.load()
for y in range(h):
    for x in range(w):
        r, g, b = px[x, y]
        a = min(1.0, max(r, g, b) / FULL)
        if a <= 0.02:
            continue
        lp[x, y] = (min(255, round(r / a)), min(255, round(g / a)), min(255, round(b / a)), round(a * 255))

bbox = logo.getbbox()
logo = logo.crop(bbox)
lw, lh = logo.size
print('logo bbox', bbox, logo.size)

def fit(im, box_w, box_h):
    s = min(box_w / im.width, box_h / im.height)
    return im.resize((max(1, round(im.width * s)), max(1, round(im.height * s))), Image.LANCZOS)

# 1. The logo alone, transparent, trimmed, with a little air around it.
pad = round(lw * 0.04)
wide = Image.new('RGBA', (lw + 2 * pad, lh + 2 * pad), (0, 0, 0, 0))
wide.paste(logo, (pad, pad), logo)
wide.save(os.path.join(OUT, 'hidranet-logo.png'), optimize=True)
fit(wide, 640, 640).save(os.path.join(OUT, 'hidranet-logo-640.png'), optimize=True)

# 2. Square, transparent: for places that want a square mark on a dark page.
S = 1024
sq = Image.new('RGBA', (S, S), (0, 0, 0, 0))
m = fit(logo, S * 0.92, S * 0.92)
sq.paste(m, ((S - m.width) // 2, (S - m.height) // 2), m)
sq.save(os.path.join(OUT, 'hidranet-logo-square.png'), optimize=True)

# 3. The app icon: the logo on a black rounded square, as on the artwork.
def tile(size, margin, radius_frac, logo_frac):
    im = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    inner = size - 2 * margin
    mask = Image.new('L', (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [margin, margin, margin + inner - 1, margin + inner - 1],
        radius=round(inner * radius_frac), fill=255)
    bg = Image.new('RGBA', (size, size), (0, 0, 0, 255))
    im.paste(bg, (0, 0), mask)
    lm = fit(logo, inner * logo_frac, inner * logo_frac)
    im.paste(lm, ((size - lm.width) // 2, (size - lm.height) // 2 + round(inner * 0.01)), lm)
    return im

icon = tile(1024, 0, 0.18, 0.86)              # Windows, Linux, web
icon.save(os.path.join(OUT, 'hidranet-icon-1024.png'), optimize=True)
for s in (512, 256, 192, 180, 128, 64, 48, 32, 16):
    icon.resize((s, s), Image.LANCZOS).save(os.path.join(OUT, f'hidranet-icon-{s}.png'), optimize=True)
# Small sizes: the logo is wide, so let it fill more of the square.
small = tile(256, 0, 0.16, 0.96)
ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
icon.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, 'hidranet.ico'), sizes=ico_sizes)
small.resize((32, 32), Image.LANCZOS).save(os.path.join(OUT, 'favicon-32.png'), optimize=True)
small.save(os.path.join(OUT, 'favicon.ico'), sizes=[(16, 16), (32, 32), (48, 48)])

# macOS: Apple's grid puts the rounded square at 824 of 1024, centred.
mac = tile(1024, 100, 0.225, 0.86)
mac.save(os.path.join(OUT, 'hidranet-macos-1024.png'), optimize=True)
mac.save(os.path.join(OUT, 'hidranet.icns'))

# Social card: the logo on black, 1200x630.
card = Image.new('RGB', (1200, 630), (0, 0, 0))
cm = fit(logo, 760, 460)
card.paste(cm, ((1200 - cm.width) // 2, (630 - cm.height) // 2), cm)
card.save(os.path.join(OUT, 'hidranet-social-1200x630.png'), optimize=True)

# And the original, untouched.
src.save(os.path.join(OUT, 'hidranet-logo-black.jpg'), quality=95)
print('done')
