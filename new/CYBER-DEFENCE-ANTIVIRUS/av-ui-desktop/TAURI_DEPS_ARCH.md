# Tauri 1.x - Arch Linux System Dependencies

The Tauri desktop UI requires WebKit/GTK libraries (`libsoup-2.4`, `javascriptcoregtk-4.0`). Install them before `npm run tauri dev`:

```bash
sudo pacman -Syu
sudo pacman -S --needed \
  webkit2gtk \
  libsoup \
  base-devel \
  curl \
  wget \
  file \
  openssl \
  appmenu-gtk-module \
  gtk3 \
  libappindicator-gtk3 \
  librsvg
```

- `webkit2gtk` provides `libjavascriptcoregtk-4.0` and `libwebkit2gtk-4.0`
- `libsoup` provides `libsoup-2.4`

Then run:

```bash
npm run tauri dev
```
