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
        """
        The first block ('genesis') is created manually with index 0
        and an arbitrary previous hash.
        """
        genesis = Block(0, "Genesis Block", "0" * 64)
        self.chain.append(genesis)

    def add_block(self, data):
        """
        Create a new block with the given data and append it to the chain.
        The new block's previous_hash is the hash of the last block.
        """
        last_block = self.chain[-1]
        new_block = Block(last_block.index + 1, data, last_block.hash)
        self.chain.append(new_block)

    def is_chain_valid(self):
        """
        Verify the integrity of the entire blockchain.
        Returns True if:
        - Every block's hash matches its recomputed hash.
        - Every block's previous_hash matches the hash of the preceding block.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Check if the stored hash is still correct
            if current.hash != current.compute_hash():
                print(f"Tampering detected: Block {current.index} hash is invalid.")
                return False

            # Check if the link to the previous block is intact
            if current.previous_hash != previous.hash:
                print(f"Tampering detected: Block {current.index} previous_hash mismatch.")
                return False

        return True

    def display_chain(self):
        """Print every block in the chain."""
        for block in self.chain:
            print(block)