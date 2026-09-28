# Encrypted-file fixtures

All passwords are `test` unless noted. These files are test data only; none is shipped in the app.

| File | Origin |
|---|---|
| `zipcrypto.zip` | made with `zip -e` |
| `enc.pdf`, `rc4.pdf`, `plain.pdf` | hand-written minimal PDFs |
| `7z-plain.7z`, `7z-psw.7z` (content encrypted, compressed index), `7z-hpsw.7z` (names encrypted) | made with py7zr 1.1.3 |
| `agile.docx` | minimal OOXML package encrypted (agile AES) with msoffcrypto-tool |
| `rar5-psw.rar`, `rar5-hpsw.rar`, `rar5-solid.rar`, `rar3-comment-psw.rar`, `rar3-comment-hpsw.rar`, `rar3-comment-plain.rar` | from the test suite of [rarfile](https://github.com/markokr/rarfile) 4.5 — Copyright (c) 2005-2026 Marko Kreen, ISC license (see below) |

rarfile license (ISC):

> Permission to use, copy, modify, and/or distribute this software for any purpose with or without
> fee is hereby granted, provided that the above copyright notice and this permission notice appear
> in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
> SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
> AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
> WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
> NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
> OF THIS SOFTWARE.
