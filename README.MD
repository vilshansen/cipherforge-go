# **CipherForge CLI \- Sikker Filkryptering (Go)**

Dette er en kommando-linje applikation skrevet i Go (Golang) designet til sikker kryptering og dekryptering af filer ved hjælp af moderne, streamende kryptografiske primitiver.

Værktøjet følger den kryptografiske konstruktion **Encrypt-then-MAC (EtM)** for at sikre både fortrolighed og autenticitet.

## **🚀 Kommandobrug**

### **Kryptering**

Krypterer en fil og gemmer den som et nyt output. Hvis intet \-p flag angives, genereres et stærkt, tilfældigt password, som skal gemmes sikkert af brugeren.

\# Standard kryptering (genererer tilfældigt password)  
go run cipherforge.go \-e \<input\_fil\> \<output\_fil\>

\# Kryptering med specifikt password  
go run cipherforge.go \-e \<input\_fil\> \<output\_fil\> \-p \<dit\_password\>

### **Dekryptering**

Dekrypterer en krypteret fil. Kræver passwordindtastning via terminalen (skjult input).

go run cipherforge.go \-d \<input\_fil\> \<output\_fil\>

## **🔐 Kryptografiske Detaljer**

### **1\. Nøglederivation (KDF)**

* **Algoritme:** **Scrypt**  
* **Formål:** At udlede kryptografisk stærke nøgler fra et (potentielt svagt) bruger-password. Scrypt er designet til at være hukommelseskrævende for at modvirke brute-force-angreb.  
* **Parametre (Konstanter i cipherforge.go):**  
  * ScryptN (Iterationer): **2^15** (32768)  
  * ScryptR (Block size): **8**  
  * ScryptP (Parallelization): **1**  
* **Outputnøgle (TotalKeySize):** 64 bytes.

### **2\. Nøgleopdeling (Encrypt-then-MAC)**

De 64 bytes, der udledes af Scrypt, opdeles i to separate nøgler for at opretholde princippet om "key separation":

| Nøgle | Størrelse | Brugt til |
| :---- | :---- | :---- |
| **EncKey** (Krypteringsnøgle) | 32 bytes (256 bit) | AES-256 CTR |
| **MacKey** (Autentificeringsnøgle) | 32 bytes (256 bit) | HMAC-SHA256 |

### **3\. Kryptering**

* **Algoritme:** **AES-256** i **Counter Mode (CTR)**.  
* **Fordele ved CTR:** Tillader streamende I/O og parallellisering, hvilket er essentielt for håndtering af store filer. Ciphertext-størrelsen er identisk med Plaintext-størrelsen.  
* **Initialization Vector (IV):** En tilfældig **16-byte Nonce** genereres for hver kryptering og gemmes i headeren.

### **4\. Autentificering (MAC)**

* **Algoritme:** **HMAC-SHA256**.  
* **Formål:** At sikre integriteten og autenticiteten af dataen og headeren.  
* **MAC-beregning:** HMAC-tagget beregnes over **hele Headeren** og **hele Ciphertexten** (de krypterede data).  
* **MAC-størrelse (TagSize):** 32 bytes (256 bit).

## **💾 Filstruktur (The CipherForge Format)**

Den krypterede outputfil er struktureret til at muliggøre streamende operationer og MAC-verifikation.

| Sektion | Størrelse | Beskrivelse |
| :---- | :---- | :---- |
| **Header** (Associeret Data) | Variabel | Metadata nødvendig for dekryptering og nøgleudledning. |
| **Ciphertext** | filesize \- Header \- Tag | De krypterede bytes fra den originale fil (ciphertext). |
| **HMAC Tag** | 32 bytes | Det beregnede HMAC-SHA256 tag. |

### **Header Detaljer**

Headeren er opbygget sekventielt:

1. **Magic Marker:** CIPHERFORGE-V00002 (Bruges til validering af filformatet).  
2. **Scrypt Parametre:** N, R, P (4 bytes hver, Big Endian).  
3. **Salt:** 16 bytes (Preceded by length).  
4. **Nonce (IV):** 16 bytes (Preceded by length).  
5. **Original Filnavn:** Base navnet på den originale inputfil (Preceded by length).

## **🛑 Sikkerhed og Integritet**

### **Encrypt-then-MAC (EtM)**

CipherForge anvender EtM-princippet, den anbefalede standard for authenticated encryption.

1. **Kryptering:** Plaintext krypteres til Ciphertext.  
2. **MAC:** HMAC beregnes over (Header \+ Ciphertext).  
3. **Output:** Filen gemmes som (Header \+ Ciphertext \+ HMAC Tag).

### **Dekryptering og Verifikation**

1. Header og HMAC Tag læses.  
2. Scrypt-nøgler udledes fra Password og Salt.  
3. En ny HMAC beregnes over (Header \+ Ciphertext).  
4. **Kritisk Skridt:** Den beregnede HMAC sammenlignes med det forventede HMAC Tag (ved hjælp af hmac.Equal).  
5. **Korrekthed:** Kun hvis HMAC'erne matcher (autentificering lykkes), fortsætter dekrypteringen af Ciphertext.

**Dette forhindrer dekryptering af manipulerede eller korrupte filer og sikrer, at kun den korrekte nøgle kan åbne filen.**