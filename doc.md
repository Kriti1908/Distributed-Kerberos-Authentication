CONTAINS ASSIGNMENT DOC

# International Institute of Information Technology Hyderabad  
## System and Network Security (CS5.470)  

# Lab Assignment 3:
## Kerberos Under Partial Compromise using Schnorr Multi-Signatures  

**Hard Deadline:** 17-03-2026, 11:59 PM  
**Total Marks:** 100  

---

## Note
It is strongly recommended that no group is allowed to copy programs from others.  
If there is any duplicate in the assignment, both parties will be given zero marks without any compromise.  
The rest of the assignments will not be evaluated further, and assignment marks will not be considered towards final grading in the course.  

No assignment will be taken after the deadline.  

Allowed languages:
- C  
- C++  
- Python  

Blind use of cryptographic libraries without protocol logic will result in heavy penalties.

---

# 1. Objective

The objective of this assignment is to design and implement a **Kerberos-inspired authentication system** resilient to **partial authority compromise** using a **2-of-3 Schnorr multi-signature scheme**.

### Definition of Partial Compromise
At most **one authentication authority** may become malicious or compromised.  
The system must continue to operate securely despite this.

Unlike classical Kerberos, this system must:
- Eliminate single-point signing authority  
- Enforce distributed trust using multi-authority signatures  

### This assignment emphasizes:
- Multi-signature authentication  
- Distributed trust  
- Compromise containment  
- Secure ticket issuance  
- Signature algebra implementation  

---

# 2. Problem Description

In classical Kerberos:
- A single Authentication Server (AS)
- A single Ticket Granting Server (TGS)

are fully trusted.

If either is compromised:
- Attacker can issue arbitrary valid tickets  
- Impersonate any user  

### Goal
Design a Kerberos-like system that remains secure even if **one authority becomes malicious**.

---

## 2.1 Architecture Overview

Your system must consist of:

- Three Authentication Authorities:  
  - AS1, AS2, AS3  

- Three Ticket Granting Authorities:  
  - TGS1, TGS2, TGS3  

- Multiple Service Servers  
- Multiple Clients  

### Constraints
- Each authority runs as a separate server process on a different port  
- Authorities **DO NOT share private key shares**

---

## 2.2 Core Security Requirement

Each authority has its own independent **Schnorr key pair**:

- Private key:  
  `xi ∈ Zq`

- Public key:  
  `yi = g^xi mod p`

### Rules
- No single authority can generate a valid ticket  
- At least **two authorities must sign**

Each authority:
- Independently signs the ticket  

A ticket is valid only if:
- At least **two signatures verify successfully**

---

## 2.3 What You Must Implement

Each authority:
- Generates its own Schnorr key pair  

Public keys:
- Known to clients and service servers  

Each authority generates:
- Independent Schnorr signature `(Ri, si)` over ticket payload  

### Validation rule
Ticket must contain:
- At least **two valid signatures**

Clients and servers:
- Verify each signature independently using `yi`

---

### Distributed TGS Operation
Same multi-signature mechanism for Service Ticket issuance.

---

### Service Verification

Service servers must:
- Verify AES encryption  
- Verify at least two Schnorr signatures  
- Reject tickets with invalid signatures  
- Reject tickets with outdated key version  

---

# 3. Threat Model

### Adversary CAN:
- Fully compromise one AS or one TGS  
- Issue forged tickets from compromised authority  
- Replay old partial signatures  
- Modify ticket contents  
- Leak one authority’s private key  

### Adversary CANNOT:
- Break discrete logarithm assumptions  
- Break AES or SHA-256  
- Compromise more than one authority  

---

# 4. System Model

- Multiple Clients  
- AS1, AS2, AS3  
- TGS1, TGS2, TGS3  
- Multiple Service Servers  

Authorities:
- Operate independently  
- Do NOT blindly trust each other  

---

# 5. Cryptographic Primitives

| Component | Requirement |
|----------|------------|
| Public Key Signature | Schnorr Multi-Signature (2-of-3) |
| Hash Function | SHA-256 |
| Symmetric Encryption | AES-256-CBC |
| Padding | Manual PKCS#7 |
| Randomness | OS-level secure RNG |

### Must implement manually:
- Modular exponentiation  
- Modular arithmetic over Zq  
- Schnorr signature generation  
- Verification of multiple Schnorr signatures  

❌ No asymmetric crypto libraries allowed  

---

# 6. Schnorr Multi-Signature Model

Each authority ASi has:

- Private key:  
  `xi ∈ Zq`

- Public key:  
  `yi = g^xi mod p`

---

## Signature Generation

For message `m`, authority i:

### Step 1: Nonce generation
`ki ∈ Zq`

### Step 2: Commitment
`Ri = g^ki mod p`

⚠️ Important:  
Each signature must use a **fresh random nonce ki**  
Reusing nonce → **private key leakage**

---

### Step 3: Challenge
`ei = H(m ∥ Ri ∥ IDi)`

### Step 4: Signature
`si = ki + ei * xi mod q`

Signature = `(Ri, si)`

---

## Verification

Verifier checks:

`g^si ≡ Ri * yi^ei mod p`

where:
`ei = H(m ∥ Ri ∥ IDi)`

### Validity Rule
Ticket is valid only if:
- At least **two independent signatures verify**

---

# 7. Protocol Phases

## Phase 1: Distributed AS Exchange

Client requests TGT from AS cluster.

Authorities respond with:
- Encrypted session key  
- Schnorr signature `(Ri, si)`  

Client:
- Collects at least two valid signatures  
- Includes them in ticket  

---

## Phase 2: Distributed TGS Exchange

Same multi-signature process for Service Ticket issuance.

---

## Phase 3: Service Authentication

Service verifies:
- At least two Schnorr signatures  
- Using authority public keys  

---

# 8. Ticket Structure

Each ticket must contain:

- Client ID  
- Service ID  
- Issue Timestamp  
- Lifetime  
- Session Key  
- Authority Metadata  
- Key Version  
- Authority Signatures `(Ri, si, AuthorityID)`  

### Ticket Requirements:
- Must be AES encrypted  
- Must be signed by at least two authorities  

---

# 9. Mandatory Attack Scenarios

Implement in `attacks.py`:

- Single malicious authority issuing forged ticket  
- Modified ticket payload  
- Replay of old partial signature  
- Leakage of one authority’s private key  
- Authority offline scenario  
- Ticket with only one valid signature  

---

# 10. Main Tasks

1. Implement Schnorr multi-signatures  
2. Verify at least two valid signatures  
3. Implement distributed AS and TGS nodes  
4. Implement ticket generation and validation  
5. Simulate authority compromise  
6. Demonstrate attack containment  
7. Provide performance analysis  

---

# 11. Submission Guidelines

Submit:

`<group_number>_lab3.zip`

### Must contain:

- master_keygen.py  
- as_node.py  
- tgs_node.py  
- service_server.py  
- client.py  
- crypto_utils.py  
- attacks.py  
- README.md  
- SECURITY.md  

---

# 12. SECURITY.md Must Explain

- Why one compromised authority cannot forge tickets  
- Why two compromised authorities break security  
- Why requiring two independent Schnorr signatures prevents forgery  
- Nonce reuse risks  
- Key share leakage impact  
- Performance overhead of multi-authority signing  

---

# 13. Evaluation Criteria

- Correct signature implementation  
- Cryptographic correctness  
- Attack handling  
- Code modularity  
- Security reasoning depth  
- Demo and viva performance  

---

# — End of Assignment —