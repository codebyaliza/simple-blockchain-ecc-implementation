"""
Lab Assignment 3 - Blockchain & ECC
Task 1: Basic Blockchain Implementation
Task 2: Elliptic Curve Cryptography (ECC) Basics
"""

import hashlib
import time
import random


# =============================================================================
# TASK 1: BASIC BLOCKCHAIN IMPLEMENTATION
# =============================================================================

class Block:
    """
    A single block in the blockchain.
    Attributes:
        index (int):       Block number (0 for genesis).
        timestamp (float): Creation time (seconds since epoch).
        data (str):        Transaction or information stored in the block.
        previous_hash (str): SHA-256 hash of the previous block.
        hash (str):        SHA-256 hash of this block.
    """
    def __init__(self, index, data, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self):
        """
        Calculate SHA-256 hash of the block's content.
        The block's identity is the hash of its index, timestamp, data and previous hash.
        """
        block_content = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
        return hashlib.sha256(block_content.encode()).hexdigest()

    def __repr__(self):
        return (f"Block(Index: {self.index}, Timestamp: {self.timestamp:.2f}, "
                f"Data: {self.data}, PrevHash: {self.previous_hash[:8]}..., "
                f"Hash: {self.hash[:8]}...)")


class Blockchain:
    """
    A simple blockchain implementation.
    The chain is a list of Block objects linked by cryptographic hashes.
    """
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """Create the first block manually."""
        genesis = Block(0, "Genesis Block", "0" * 64)
        self.chain.append(genesis)

    def add_block(self, data):
        """Append a new block with the given data."""
        last_block = self.chain[-1]
        new_block = Block(last_block.index + 1, data, last_block.hash)
        self.chain.append(new_block)

    def is_chain_valid(self):
        """
        Verify the integrity of the entire blockchain.
        Returns True if every block's hash is valid and links are correct.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.compute_hash():
                print(f"Tampering detected: Block {current.index} hash is invalid.")
                return False

            if current.previous_hash != previous.hash:
                print(f"Tampering detected: Block {current.index} previous_hash mismatch.")
                return False

        return True

    def display_chain(self):
        """Print every block in the chain."""
        for block in self.chain:
            print(block)


# =============================================================================
# TASK 2: ELLIPTIC CURVE CRYPTOGRAPHY (ECC) BASICS
# =============================================================================

class ECC:
    """
    Elliptic curve of the form y^2 = x^3 + ax + b (mod p).
    Provides point addition, doubling, scalar multiplication, and
    a simplified EC-ElGamal encryption/decryption.
    """
    def __init__(self, a, b, p):
        """
        Initialize curve parameters.
        a, b: coefficients of the curve equation.
        p   : prime modulus (finite field F_p).
        """
        self.a = a
        self.b = b
        self.p = p
        # Check non-singularity: 4a^3 + 27b^2 != 0 mod p
        if (4 * a**3 + 27 * b**2) % p == 0:
            raise ValueError("Curve is singular, choose different parameters.")

    def is_on_curve(self, x, y):
        """Return True if (x,y) lies on the curve."""
        return (y**2) % self.p == (x**3 + self.a * x + self.b) % self.p

    def mod_inverse(self, k):
        """Compute modular inverse of k modulo p."""
        if k % self.p == 0:
            raise ZeroDivisionError("Inverse does not exist.")
        return pow(k, -1, self.p)   # Python 3.8+ supports negative exponent

    def point_add(self, P, Q):
        """
        Add two points P and Q on the curve.
        Returns (x3, y3) or None (point at infinity) if P = -Q.
        """
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and y1 != y2:
            # P + (-P) = point at infinity
            return None

        if P != Q:
            # Standard addition
            m = ((y2 - y1) * self.mod_inverse(x2 - x1)) % self.p
        else:
            # Point doubling
            if y1 == 0:
                # Doubling a point with y=0 gives the point at infinity
                return None
            m = ((3 * x1**2 + self.a) * self.mod_inverse(2 * y1)) % self.p

        x3 = (m**2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def scalar_mult(self, k, P):
        """
        Multiply a point P by an integer k (double-and-add algorithm).
        Returns k*P.
        """
        if P is None:
            return None

        result = None                # Point at infinity
        addend = P

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result

    def find_point_from_x(self, x):
        """
        Given an x-coordinate, find a point (x, y) on the curve.
        Brute‑force suitable only for very small p.
        """
        rhs = (x**3 + self.a * x + self.b) % self.p
        for y in range(self.p):
            if (y * y) % self.p == rhs:
                return (x, y)
        return None

    def encode_message(self, m):
        """
        Convert a small integer message m into a point on the curve.
        Tries x = m, m+1, ... until a valid y exists.
        """
        x = m
        while x < self.p:
            point = self.find_point_from_x(x)
            if point:
                return point
            x += 1
        raise ValueError("Could not encode message – increase message space.")


def ecc_demo():
    """Demonstrate ECC key generation, encryption and decryption."""
    print("\nTASK 2: ECC Demonstration")
    curve = ECC(a=0, b=7, p=17)

    # Generator point (must be on the curve)
    G = (1, 5)
    print(f"Curve: y^2 = x^3 + 7 (mod 17), Generator G = {G}")

    # Key generation
    private_key = random.randint(2, curve.p - 1)
    public_key = curve.scalar_mult(private_key, G)
    print(f"Private key (d): {private_key}")
    print(f"Public key (Q = d*G): {public_key}")

    # Encrypt a small numeric message (e.g., 9)
    message = 9
    print(f"\nOriginal message (numeric): {message}")
    M = curve.encode_message(message)
    print(f"Encoded message point M: {M}")

    # ElGamal encryption: C1 = k*G, C2 = M + k*Q
    k = random.randint(2, curve.p - 1)
    C1 = curve.scalar_mult(k, G)
    shared_secret = curve.scalar_mult(k, public_key)
    C2 = curve.point_add(M, shared_secret)
    print(f"Ciphertext: C1 = {C1}, C2 = {C2}")

    # Decryption: shared secret = d*C1, then M = C2 - d*C1
    decrypt_shared = curve.scalar_mult(private_key, C1)
    # Subtract: add the inverse (x, -y mod p)
    inv_shared = (decrypt_shared[0], (-decrypt_shared[1]) % curve.p)
    M_decrypted = curve.point_add(C2, inv_shared)
    print(f"Decrypted message point: {M_decrypted}")

    # Recover original message (x-coordinate of M)
    recovered_message = M_decrypted[0]
    print(f"Recovered numeric message: {recovered_message}")


# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    print("=== Task 1: Basic Blockchain ===")
    bc = Blockchain()
    bc.add_block("Alice pays Bob 10 coins")
    bc.add_block("Bob pays Charlie 5 coins")
    bc.add_block("Charlie pays Dave 2 coins")
    bc.add_block("Dave pays Alice 1 coin")
    bc.display_chain()

    print("\nBlockchain valid?", bc.is_chain_valid())

    # Tampering demonstration
    print("\n--- Tampering block 1's data ---")
    bc.chain[1].data = "Alice pays Bob 1000 coins"
    print("Blockchain valid after tampering?", bc.is_chain_valid())

    print("\n")
    ecc_demo()