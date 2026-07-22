# CryptoSentry

Educational RSA demo and quantum-threat (Shor) simulation.

## Overview

RSA's security rests on integer factorization being hard classically, and Shor's algorithm is the standard example of why a sufficiently large quantum computer would break that assumption. This project is a small, hands-on way to see the two sides of that story: generate a real (but deliberately tiny) RSA key pair, "factor" it back apart the way a period-finding attack would, and plot how the risk changes as key length grows. It is meant to make the concept concrete, not to demonstrate an actual quantum attack.

## Method

The RSA key generation is textbook RSA with toy parameters: two small primes (1237 and 1657) instead of the 1024+ bit primes a real key would use, the usual public exponent 65537, and the private exponent recovered via the extended Euclidean algorithm. A short message is encrypted with the resulting public key to confirm the keypair works.

The "Shor" step does not run a quantum period-finding routine, since that requires actual quantum hardware or a simulator well beyond the scope of a demo script. Instead it factors the modulus classically by trial division, and reports `log(n)` as a stand-in for the deep speedup a real quantum algorithm would provide over classical factoring. The risk analysis takes that same idea across a range of key lengths (512 to 4096 bits) and turns it into a simple, illustrative score.

None of this is a working quantum simulator or a production cryptography implementation. The key sizes are toy-scale specifically so the factoring step finishes instantly, and the risk score is a rough illustration of the relationship between key length and attack cost, not a calibrated security metric.

## Results

![Quantum vulnerability analysis](assets/quantum_analysis.png)

The 3D scatter plots risk score against key length and (log-scaled) quantum attack time for the four key sizes considered. The shorter keys sit at higher risk scores and the trend flattens out as key length grows, which is the qualitative point the demo is making: longer RSA keys buy a real margin against a period-finding style attack, even in this simplified model.

## Getting started

```bash
git clone https://github.com/poggymacello/cryptosentry.git
cd cryptosentry
python3 -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
python3 src/cryptosentry.py
```

Running the script generates the toy RSA key pair, factors it back apart, computes the risk scores across key lengths, and writes `assets/quantum_analysis.png`.

## Project structure

```
cryptosentry/
├── src/cryptosentry.py     # RSA keygen, factoring simulation, risk analysis, plot
├── assets/                  # generated output (vulnerability analysis plot)
├── requirements.txt
├── LICENSE
└── README.md
```

## License

MIT, see [LICENSE](LICENSE).
