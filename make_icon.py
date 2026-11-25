"""make_icon.py - draws the DockerScan cricket-bat icon (icon.png + icon.ico). Needs Pillow."""
from PIL import Image, ImageDraw, ImageFilter

S = 1024
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# dark navy rounded tile with neon cyan border
d.rounded_rectangle((20, 20, S - 20, S - 20), radius=210, fill=(7, 12, 36, 255), outline=(0, 229, 255, 255), width=22)
d.rounded_rectangle((60, 60, S - 60, S - 60), radius=180, outline=(168, 85, 247, 150), width=8)

# draw the bat upright on its own layer, then rotate it 40 degrees
bat = Image.new("RGBA", (S, S), (0, 0, 0, 0))
b = ImageDraw.Draw(bat)
cx = S // 2
b.rounded_rectangle((cx - 28, 150, cx + 28, 400), radius=20, fill=(30, 30, 40, 255))          # handle
for y in range(190, 380, 38):                                                                   # grip bands
    b.rectangle((cx - 28, y, cx + 28, y + 14), fill=(0, 229, 255, 255))
b.polygon([(cx - 28, 395), (cx + 28, 395), (cx + 62, 450), (cx - 62, 450)], fill=(214, 164, 92, 255))  # shoulder
b.rounded_rectangle((cx - 100, 440, cx + 100, 880), radius=36, fill=(236, 190, 112, 255))      # blade
b.rounded_rectangle((cx - 100, 440, cx - 40, 880), radius=36, fill=(250, 214, 150, 255))       # highlight
b.rectangle((cx + 10, 470, cx + 16, 850), fill=(200, 150, 80, 255))                             # spine line
b.rounded_rectangle((cx - 100, 840, cx + 100, 880), radius=20, fill=(160, 110, 55, 255))        # toe edge
bat = bat.rotate(40, resample=Image.BICUBIC, center=(S // 2, S // 2))
glow = bat.filter(ImageFilter.GaussianBlur(26))
img.alpha_composite(Image.merge("RGBA", (glow.split()[0].point(lambda v: 0), glow.split()[0].point(lambda v: 229),
                                         glow.split()[0].point(lambda v: 255), glow.split()[3].point(lambda v: v // 2))))
img.alpha_composite(bat)

# cricket ball (red with white seam) bottom-left
d = ImageDraw.Draw(img)
bx, by, r = 270, 740, 120
d.ellipse((bx - r, by - r, bx + r, by + r), fill=(220, 30, 60, 255), outline=(255, 255, 255, 255), width=6)
d.ellipse((bx - 42, by - r + 10, bx + 42, by + r - 10), outline=(255, 255, 255, 255), width=7)  # seam

img.save("icon.png")
img.save("icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icon.png and icon.ico created")
