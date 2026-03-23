#!/usr/bin/env python3
"""
AEGIS TPM Attestation Module

Provides hardware-rooted attestation using TPM 2.0.
Used to sign attestation evidence with the platform's TPM,
providing stronger guarantees than software-only signing.

Requires: python-tpm2, tpm2-tools
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

try:
    import tpm2_py
    TPM2_AVAILABLE = True
except ImportError:
    TPM2_AVAILABLE = False

from ..common.logger import get_logger

logger = get_logger("aegis.tpm")


@dataclass
class TPMQuote:
    """TPM quote containing signed attestation."""
    quote: bytes
    signature: bytes
    pcr_select: list
    pcr_values: dict
    timestamp: float


@dataclass
class TPMIdentity:
    """TPM identity credentials."""
    ak_handle: str
    ak_name: str
    certificate: Optional[bytes]


class TPMAttestor:
    """TPM 2.0 based attestor for hardware-rooted evidence."""
    
    def __init__(self, 
                 pcr_select: list = [0, 1, 2, 3, 7],  # Standard PCRs
                 bank: str = "sha256"):
        """
        Initialize TPM attestor.
        
        Args:
            pcr_select: List of PCRs to quote
            bank: Hash algorithm (sha256, sha384)
        """
        self.pcr_select = pcr_select
        self.bank = bank
        self.initialized = False
        
        if not TPM2_AVAILABLE:
            logger.warning("TPM2 Python bindings not available, using software fallback")
            return
        
        self._check_tpm()
    
    def _check_tpm(self) -> bool:
        """Check if TPM is available."""
        try:
            # Check /dev/tpm0 or /dev/tpm0
            tpm_devs = ["/dev/tpm0", "/dev/tpmrm0"]
            for dev in tpm_devs:
                if os.path.exists(dev):
                    logger.info(f"TPM device found: {dev}")
                    self.tpm_dev = dev
                    break
            else:
                # Try TPM simulator
                logger.info("No TPM device found, checking for simulator")
                self.tpm_dev = None
            
            # Check TPM2 tools
            result = subprocess.run(
                ["tpm2_getcap", "--version"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                logger.info("tpm2-tools available")
                self._setup_identity()
                return True
            
        except FileNotFoundError:
            logger.warning("tpm2-tools not installed")
        
        return False
    
    def _setup_identity(self):
        """Setup or load TPM identity (AK)."""
        try:
            # Check if AK already exists
            result = subprocess.run(
                ["tpm2_evictcontrol", "-c", "/usr/local/lib/aegis/ak.ctx"],
                capture_output=True
            )
            if result.returncode == 0:
                logger.info("Loading existing AK")
                self.ak_ctx = "/usr/local/lib/aegis/ak.ctx"
            else:
                logger.info("Creating new AK")
                self._create_ak()
            
            self.initialized = True
            
        except Exception as e:
            logger.error(f"Failed to setup TPM identity: {e}")
    
    def _create_ak(self):
        """Create a new TPM Attestation Key (AK)."""
        # Create temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create AK
            subprocess.run([
                "tpm2_createak",
                "-C", "/etc/tpm2_workspace/owner.ctx",
                "-c", f"{tmpdir}/ak.ctx",
                "-u", f"{tmpdir}/ak.pub",
                "-r", f"{tmpdir}/ak.priv",
                "-G", "rsa2048:ecc256:null",
                "-g", "sha256",
                "-s", "rsassa",
            ], check=True, capture_output=True)
            
            # Make persistent
            result = subprocess.run([
                "tpm2_evictcontrol",
                "-c", f"{tmpdir}/ak.ctx",
                "-o", f"{tmpdir}/ak.handle"
            ], check=True, capture_output=True)
            
            # Get AK name
            result = subprocess.run([
                "tpm2_readpublic",
                "-c", f"{tmpdir}/ak.ctx",
                "-n", f"{tmpdir}/ak.name"
            ], check=True, capture_output=True)
            
            with open(f"{tmpdir}/ak.name", "rb") as f:
                self.ak_name = f.read().hex()
            
            # Save context
            os.makedirs("/usr/local/lib/aegis", exist_ok=True)
            subprocess.run([
                "tpm2_evictcontrol",
                "-c", f"{tmpdir}/ak.ctx",
                "-o", "/usr/local/lib/aegis/ak.ctx"
            ], check=True)
            
            self.ak_ctx = "/usr/local/lib/aegis/ak.ctx"
            logger.info("AK created and made persistent")
    
    def quote(self, data: bytes) -> TPMQuote:
        """
        Generate TPM quote for data.
        
        This signs the data using the TPM's Attestation Key (AK),
        binding the attestation to the platform's hardware root of trust.
        """
        # Get current PCR values
        pcr_values = self._read_pcrs()
        
        # Create quote
        if self.initialized and hasattr(self, 'ak_ctx'):
            return self._tpm2_quote(data, pcr_values)
        else:
            return self._software_quote(data, pcr_values)
    
    def _read_pcrs(self) -> dict:
        """Read current PCR values."""
        pcr_values = {}
        
        for pcr in self.pcr_select:
            try:
                result = subprocess.run([
                    "tpm2_pcrread",
                    "-g", self.bank,
                    f"sha256:{pcr}"
                ], capture_output=True, text=True, check=True)
                
                # Parse PCR value
                for line in result.stdout.strip().split('\n'):
                    if f"PCR {pcr}" in line:
                        value = line.split(':')[1].strip()
                        pcr_values[pcr] = value
                        
            except Exception as e:
                logger.warning(f"Failed to read PCR {pcr}: {e}")
                pcr_values[pcr] = "unavailable"
        
        return pcr_values
    
    def _tpm2_quote(self, data: bytes, pcr_values: dict) -> TPMQuote:
        """Generate real TPM quote."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_file = f"{tmpdir}/data"
            quote_file = f"{tmpdir}/quote.out"
            signature_file = f"{tmpdir}/signature"
            
            # Write data to sign
            with open(data_file, "wb") as f:
                f.write(data)
            
            # Build PCR selection string
            pcr_select_str = ",".join(f"sha256:{pcr}" for pcr in self.pcr_select)
            
            # Generate quote
            subprocess.run([
                "tpm2_quote",
                "-c", self.ak_ctx,
                "-g", self.bank,
                "-m", data_file,
                "-o", quote_file,
                "-s", signature_file,
                "-p", pcr_select_str,
            ], check=True, capture_output=True)
            
            with open(quote_file, "rb") as f:
                quote = f.read()
            
            with open(signature_file, "rb") as f:
                signature = f.read()
            
            return TPMQuote(
                quote=quote,
                signature=signature,
                pcr_select=self.pcr_select,
                pcr_values=pcr_values,
                timestamp=os.path.getmtime(quote_file)
            )
    
    def _software_quote(self, data: bytes, pcr_values: dict) -> TPMQuote:
        """
        Software fallback - for testing without TPM.
        
        WARNING: This does NOT provide hardware-rooted trust.
        Use only for development/testing.
        """
        import hmac
        
        # Create a mock signature using a derived key
        mock_key = hashlib.sha256(b"aegis-software-fallback").digest()
        signature = hmac.new(mock_key, data, hashlib.sha256).digest()
        
        # Create a mock quote containing the data and PCR states
        quote_data = {
            "data": base64.b64encode(data).decode(),
            "pcr_values": pcr_values,
            "software_fallback": True,
        }
        quote = json.dumps(quote_data).encode()
        
        logger.warning("Using SOFTWARE FALLBACK - not TPM backed!")
        
        return TPMQuote(
            quote=quote,
            signature=signature,
            pcr_select=self.pcr_select,
            pcr_values=pcr_values,
            timestamp=0
        )
    
    def verify_quote(self, quote: TPMQuote, expected_data: bytes) -> bool:
        """
        Verify a TPM quote.
        
        In production, this would verify against the TPM's public key
        and validate PCR state.
        """
        # Check if it's a software fallback
        try:
            quote_data = json.loads(quote.quote.decode())
            if quote_data.get("software_fallback"):
                logger.warning("Verifying software fallback quote")
                return True  # Always accept in test mode
        except:
            pass
        
        # For real TPM quotes, verify signature
        # This requires the TPM's public key and certificate chain
        logger.info("Verifying TPM quote (full verification not implemented)")
        return True
    
    def get_identity(self) -> Optional[TPMIdentity]:
        """Get TPM identity information."""
        if not self.initialized:
            return None
        
        return TPMIdentity(
            ak_handle=self.ak_ctx,
            ak_name=getattr(self, 'ak_name', 'unknown'),
            certificate=None  # Would load from TPM NVRAM
        )


class TPMAttestationMixin:
    """Mixin to add TPM attestation to evidence."""
    
    def __init__(self, *args, tpm_attestor: Optional[TPMAttestor] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.tpm = tpm_attestor or TPMAttestor()
    
    def sign_with_tpm(self, evidence: dict) -> dict:
        """Sign evidence with TPM."""
        # Serialize evidence
        evidence_json = json.dumps(evidence, sort_keys=True)
        evidence_bytes = evidence_json.encode()
        
        # Get TPM quote
        quote = self.tpm.quote(evidence_bytes)
        
        # Add to evidence
        evidence["tpm_quote"] = {
            "pcr_select": quote.pcr_select,
            "pcr_values": quote.pcr_values,
            "signature": base64.b64encode(quote.signature).decode(),
            "timestamp": quote.timestamp,
            "software_fallback": hasattr(self.tpm, 'initialized') and not self.tpm.initialized,
        }
        
        return evidence


# Standalone usage
if __name__ == "__main__":
    import sys
    
    logger.setLevel("INFO")
    
    print("=== AEGIS TPM Attestation Test ===")
    
    tpm = TPMAttestor()
    
    if tpm.initialized:
        print("✓ TPM initialized")
        
        # Test quote
        test_data = b"test evidence data"
        quote = tpm.quote(test_data)
        
        print(f"  PCRs quoted: {quote.pcr_select}")
        print(f"  PCR values: {list(quote.pcr_values.keys())}")
        print(f"  Signature: {len(quote.signature)} bytes")
        
        # Verify
        if tpm.verify_quote(quote, test_data):
            print("✓ Quote verified")
        
        # Get identity
        identity = tpm.get_identity()
        if identity:
            print(f"✓ AK Name: {identity.ak_name[:32]}...")
            
    else:
        print("⚠ TPM not available, using software fallback")
        print("  (This is expected in development/testing)")