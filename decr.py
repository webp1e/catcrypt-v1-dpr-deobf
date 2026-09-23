#!/usr/bin/env python3

import sys
import os
import argparse

XOR_KEY = bytes([19, 55, 222, 173])
BUFFER_SIZE = 8192


def decrypt_bytes(data, start_offset=0):
    out = bytearray(len(data))
    for i, b in enumerate(data):
        v = (b - 105 + 256) % 256
        v ^= XOR_KEY[(start_offset + i) % len(XOR_KEY)]
        out[i] = v
    return bytes(out)


def decrypt_file(path, remove_original=True):
    if not path.endswith(".pdr"):
        raise ValueError(f"Не .pdr файл: {path}")

    out_path = path[: -len(".pdr")]
    tmp_path = out_path + ".dec.tmp"

    total = 0
    try:
        with open(path, "rb") as fin, open(tmp_path, "wb") as fout:
            while True:
                chunk = fin.read(BUFFER_SIZE)
                if not chunk:
                    break
                fout.write(decrypt_bytes(chunk, total))
                total += len(chunk)

        if os.path.getsize(tmp_path) != os.path.getsize(path):
            raise IOError("Размер не совпал, расшифровка прервана")

        if os.path.exists(out_path):
            os.remove(out_path)
        os.rename(tmp_path, out_path)

        if remove_original:
            os.remove(path)

        return out_path

    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def crawl_and_decrypt(root, remove_original=True):
    for dirpath, dirnames, filenames in os.walk(root):
        low = dirpath.lower()
        if any(s in low for s in ("\\windows", "\\program files",
                                  "\\program files (x86)", "\\appdata",
                                  "$recycle.bin")):
            dirnames[:] = []
            continue

        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                if name.endswith(".pdr"):
                    print(f"Расшифровываю: {full}")
                    decrypt_file(full, remove_original)
                elif name.endswith(".pdr.tmp"):
                    base = full[: -len(".pdr.tmp")]
                    if not os.path.exists(base):
                        tmp2 = full[: -len(".tmp")]
                        if os.path.exists(tmp2):
                            os.remove(tmp2)
                        os.rename(full, tmp2)
                        print(f"Восстанавливаю: {tmp2}")
                        decrypt_file(tmp2, remove_original)
            except Exception as e:
                print(f"Ошибка: {full} - {e}")


def main():
    ap = argparse.ArgumentParser(description="CatCrypt v1 расшифровщик .pdr")
    ap.add_argument("paths", nargs="*", help=".pdr файлы")
    ap.add_argument("--dir", help="Рекурсивно обойти каталог")
    ap.add_argument("--keep", action="store_true",
                    help="Не удалять исходный .pdr после расшифровки")
    args = ap.parse_args()

    remove_original = not args.keep

    if args.dir:
        crawl_and_decrypt(args.dir, remove_original)
        return

    if not args.paths:
        ap.print_help()
        sys.exit(1)

    for p in args.paths:
        try:
            out = decrypt_file(p, remove_original)
            print(f"Готово: {p} -> {out}")
        except Exception as e:
            print(f"Не вышло: {p} - {e}")


if __name__ == "__main__":
    main()