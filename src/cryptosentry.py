# Eh ini skrip buat simulasi RSA sama analisis keamanan kuantum
# Dibuat pas lagi gabut sambil ngopi di warung, terinspirasi dari paper lama Rivest
# Yang penting jalan dulu lah ya, optimisasi belakangan

import os
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import random
import time
import math

def bikin_kunci_rsa():
    """
    Fungsi buat bikin kunci RSA
    Sebenernya harusnya 2048-bit sih, tapi males tunggu lama
    jadi pake angka kecil aja buat demo
    """
    # Pura-puranya ini prime gede ya.. hehe
    p = 1237  # Harusnya 2048-bit prime
    q = 1657  # Ini juga
    
    n = p * q  # Modulus RSA
    phi = (p-1) * (q-1)  # Totient-nya Euler
    
    # e nya pake yang standar aja lah ya
    e = 65537  # Males mikir nilai lain
    
    # Cari d pake extended euclidean
    # Ini agak ribet sih tapi ya sudahlah
    def cari_d(e, phi):
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            else:
                g, x, y = egcd(b % a, a)
                return g, y - (b // a) * x, x

        _, d, _ = egcd(e, phi)
        d = d % phi
        if d < 0:
            d += phi
        return d
    
    d = cari_d(e, phi)
    
    # Coba enkripsi "Halo" buat test
    pesan = "Halo"
    print(f"\nCoba enkripsi pesan: {pesan}")
    enkripsi = [pow(ord(c), e, n) for c in pesan]
    print(f"Hasil enkripsi (angka doang): {enkripsi[:20]}...")
    
    return (e, n), (d, n)

def simulasi_shor(n):
    """
    Simulasi algoritma Shor buat faktorisasi
    Sebenernya ga gini sih cara kerjanya, tapi anggep aja ini versi simplified
    """
    print("\nMulai simulasi Shor...")
    # Pura-pura ini quantum period finding
    waktu_mulai = time.time()
    
    # Loop klasik (sebenernya Shor ga gini, tapi ya sudahlah)
    p = None
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            p = i
            break
    
    q = n // p if p else None
    waktu_quantum = math.log(n)  # Harusnya lebih cepet
    
    print(f"Ketemu faktor: {p} dan {q}")
    return p, q, waktu_quantum

def analisis_risiko(panjang_kunci, waktu_quantum):
    """
    Ngitung level risiko berdasarkan waktu serangan
    Makin cepet = makin bahaya
    """
    skor_risiko = []
    for t in waktu_quantum:
        # Rumus ngasal tapi kedengerannya masuk akal
        risiko = 1 / (1 + math.log(t))
        skor_risiko.append(risiko)
    
    return np.array(skor_risiko)

def bikin_plot_3d(panjang_kunci, waktu_quantum, skor_risiko):
    """
    Bikin visualisasi 3D yang keliatan keren
    Biar pas presentasi ke bos ada wah-nya dikit
    """
    # Pake style default aja deh, yang penting jalan
    plt.style.use('default')
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, projection='3d')
    
    # Scatter plot dengan warna berdasarkan risiko
    scatter = ax.scatter(panjang_kunci, waktu_quantum, skor_risiko,
                        c=skor_risiko, cmap='RdYlGn_r', s=100)
    
    # Nambahin label
    ax.set_xlabel('Panjang Kunci (bit)')
    ax.set_ylabel('Waktu Serangan Kuantum (log)')
    ax.set_zlabel('Skor Risiko')
    
    plt.title('Analisis Kerentanan Kuantum', pad=20)
    plt.colorbar(scatter, label='Level Risiko')
    
    # Rotasi view biar keliatan keren
    ax.view_init(30, 45)

    assets_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'assets')
    os.makedirs(assets_dir, exist_ok=True)
    output_path = os.path.join(assets_dir, 'quantum_analysis.png')
    plt.savefig(output_path)
    print(f"\nVisualisasi sudah disimpan sebagai '{output_path}'")

if __name__ == "__main__":
    print("=== CryptoSentry: Analisis Keamanan RSA vs Kuantum ===")
    print("(Dibuat pas lagi gabut di warung kopi)")
    
    try:
        # Bikin kunci RSA dulu
        print("\nStep 1: Bikin kunci RSA...")
        pub_key, priv_key = bikin_kunci_rsa()
        print(f"Kunci publik: {pub_key}")
        print(f"Kunci privat: {priv_key}")
        
        # Simulasi Shor
        print("\nStep 2: Coba faktorin pake 'Shor'...")
        p, q, waktu = simulasi_shor(pub_key[1])
        
        # Analisis buat beberapa panjang kunci
        print("\nStep 3: Analisis risiko...")
        panjang_kunci = np.array([512, 1024, 2048, 4096])
        waktu_quantum = np.array([math.log(k) for k in panjang_kunci])
        skor_risiko = analisis_risiko(panjang_kunci, waktu_quantum)
        
        # Bikin plot 3D yang keren
        print("\nStep 4: Bikin visualisasi...")
        print("(Tunggu bentar, matplotlib loading...)")
        bikin_plot_3d(panjang_kunci, waktu_quantum, skor_risiko)
        
    except Exception as e:
        print(f"\nYah error: {str(e)}")
        print("Coba jalanin ulang deh, kadang suka gitu...")
