"""
Threat Intelligence Scoring Module

Simple scoring system for threat correlation based on Diamond Model evidence weights.
Given two rows from enriched threat data, calculates a similarity score.
"""

from typing import Dict, Tuple, Any


class ThreatScorer:
    """
    Simple threat scoring based on Diamond Model evidence weights.
    """
    
    # Evidence weights based on Diamond Model framework
    EVIDENCE_WEIGHTS = {
        # Infrastructure Evidence
        'cert_serial_issuer': 5.0,      # Certificate serial + issuer combination
        'ip_address': 3.0,              # Exact IP address match
        'cidr_block': 2.5,              # CIDR block overlap
        'name_servers': 2.0,            # Name server sharing
        'registrar': 1.8,               # Domain registrar
        'hosting_asn': 1.5,             # Hosting ASN
        
        # Victim Evidence
        'target_brand': 4.0,            # Targeted brand/organization
        
        # Capability Evidence
        'cert_fingerprint': 3.5,        # Certificate fingerprint
        'url_pattern': 2.8,             # URL structure patterns
    }
    
    def __init__(self, custom_weights: Dict[str, float] = None):
        """
        Initialize scorer with optional custom weights.
        
        Args:
            custom_weights: Optional custom evidence weights
        """
        self.weights = self.EVIDENCE_WEIGHTS.copy()
        if custom_weights:
            self.weights.update(custom_weights)
    
    def score_threats(self, threat1: Dict[str, Any], threat2: Dict[str, Any]) -> float:
        """
        Calculate similarity score between two threat records.
        
        Args:
            threat1: First threat record from enriched_threats table
            threat2: Second threat record from enriched_threats table
            
        Returns:
            Total similarity score
        """
        total_score = 0.0
        
        # Check each evidence type
        for evidence_type, weight in self.weights.items():
            similarity = self._calculate_evidence_similarity(threat1, threat2, evidence_type)
            if similarity > 0:
                total_score += weight * similarity
        
        return total_score
    
    def _calculate_evidence_similarity(self, threat1: Dict[str, Any], threat2: Dict[str, Any], 
                                     evidence_type: str) -> float:
        """
        Calculate similarity for specific evidence type.
        
        Returns:
            Similarity score between 0.0 and 1.0
        """
        if evidence_type == 'cert_serial_issuer':
            return self._compare_cert_serial_issuer(threat1, threat2)
        elif evidence_type == 'ip_address':
            return self._compare_ip_addresses(threat1, threat2)
        elif evidence_type == 'cidr_block':
            return self._compare_cidr_blocks(threat1, threat2)
        elif evidence_type == 'name_servers':
            return self._compare_name_servers(threat1, threat2)
        elif evidence_type == 'registrar':
            return self._compare_registrars(threat1, threat2)
        elif evidence_type == 'hosting_asn':
            return self._compare_hosting_asn(threat1, threat2)
        elif evidence_type == 'target_brand':
            return self._compare_target_brands(threat1, threat2)
        elif evidence_type == 'cert_fingerprint':
            return self._compare_cert_fingerprints(threat1, threat2)
        elif evidence_type == 'url_pattern':
            return self._compare_url_patterns(threat1, threat2)
        else:
            return 0.0
    
    def _compare_cert_serial_issuer(self, threat1: Dict, threat2: Dict) -> float:
        """Compare certificate serial number and issuer combination."""
        cert1_serial = str(threat1.get('cert_serial_number', '')).strip()
        cert1_issuer = str(threat1.get('cert_issuer', '')).strip()
        cert2_serial = str(threat2.get('cert_serial_number', '')).strip()
        cert2_issuer = str(threat2.get('cert_issuer', '')).strip()
        
        if not all([cert1_serial, cert1_issuer, cert2_serial, cert2_issuer]):
            return 0.0
        
        if (cert1_serial.lower() == cert2_serial.lower() and 
            cert1_issuer.lower() == cert2_issuer.lower()):
            return 1.0
        
        return 0.0
    
    def _compare_ip_addresses(self, threat1: Dict, threat2: Dict) -> float:
        """Compare IP addresses."""
        ip1 = str(threat1.get('ip_address', '')).strip()
        ip2 = str(threat2.get('ip_address', '')).strip()
        
        if not ip1 or not ip2:
            return 0.0
        
        return 1.0 if ip1 == ip2 else 0.0
    
    def _compare_cidr_blocks(self, threat1: Dict, threat2: Dict) -> float:
        """Compare CIDR block overlap."""
        ip1 = str(threat1.get('ip_address', '')).strip()
        ip2 = str(threat2.get('ip_address', '')).strip()
        
        if not ip1 or not ip2:
            return 0.0
        
        try:
            import ipaddress
            
            # Check /24 subnet overlap
            addr1 = ipaddress.ip_address(ip1)
            addr2 = ipaddress.ip_address(ip2)
            
            network1_24 = ipaddress.ip_network(f"{addr1}/24", strict=False)
            network2_24 = ipaddress.ip_network(f"{addr2}/24", strict=False)
            
            if network1_24 == network2_24:
                return 0.8  # High similarity for same /24
            
            # Check /16 subnet overlap
            network1_16 = ipaddress.ip_network(f"{addr1}/16", strict=False)
            network2_16 = ipaddress.ip_network(f"{addr2}/16", strict=False)
            
            if network1_16 == network2_16:
                return 0.4  # Medium similarity for same /16
            
        except ValueError:
            return 0.0
        
        return 0.0
    
    def _compare_name_servers(self, threat1: Dict, threat2: Dict) -> float:
        """Compare name servers."""
        ns1 = str(threat1.get('name_servers', '')).strip()
        ns2 = str(threat2.get('name_servers', '')).strip()
        
        if not ns1 or not ns2:
            return 0.0
        
        # Parse name servers (comma-separated)
        ns1_set = set(ns.strip().lower() for ns in ns1.split(',') if ns.strip())
        ns2_set = set(ns.strip().lower() for ns in ns2.split(',') if ns.strip())
        
        if not ns1_set or not ns2_set:
            return 0.0
        
        intersection = ns1_set & ns2_set
        if intersection:
            # Return overlap ratio
            return len(intersection) / max(len(ns1_set), len(ns2_set))
        
        return 0.0
    
    def _compare_registrars(self, threat1: Dict, threat2: Dict) -> float:
        """Compare domain registrars."""
        reg1 = str(threat1.get('registrar', '')).strip().lower()
        reg2 = str(threat2.get('registrar', '')).strip().lower()
        
        if not reg1 or not reg2:
            return 0.0
        
        return 1.0 if reg1 == reg2 else 0.0
    
    def _compare_hosting_asn(self, threat1: Dict, threat2: Dict) -> float:
        """Compare hosting ASN."""
        asn1 = str(threat1.get('hosting_asn', '')).strip()
        asn2 = str(threat2.get('hosting_asn', '')).strip()
        
        if not asn1 or not asn2:
            return 0.0
        
        return 1.0 if asn1 == asn2 else 0.0
    
    def _compare_target_brands(self, threat1: Dict, threat2: Dict) -> float:
        """Compare targeted brands."""
        brand1 = str(threat1.get('brand', '')).strip().lower()
        brand2 = str(threat2.get('brand', '')).strip().lower()
        
        if not brand1 or not brand2:
            return 0.0
        
        return 1.0 if brand1 == brand2 else 0.0
    
    def _compare_cert_fingerprints(self, threat1: Dict, threat2: Dict) -> float:
        """Compare certificate fingerprints."""
        fp1 = str(threat1.get('cert_fingerprint', '')).strip().lower()
        fp2 = str(threat2.get('cert_fingerprint', '')).strip().lower()
        
        if not fp1 or not fp2:
            return 0.0
        
        return 1.0 if fp1 == fp2 else 0.0
    
    def _compare_url_patterns(self, threat1: Dict, threat2: Dict) -> float:
        """Compare URL patterns."""
        url1 = str(threat1.get('indicator', '')).strip().lower()
        url2 = str(threat2.get('indicator', '')).strip().lower()
        
        if not url1 or not url2:
            return 0.0
        
        # Simple domain similarity check
        try:
            domain1 = self._extract_domain(url1)
            domain2 = self._extract_domain(url2)
            
            if domain1 and domain2:
                # Basic string similarity
                similarity = self._string_similarity(domain1, domain2)
                return similarity if similarity > 0.7 else 0.0
        except:
            pass
        
        return 0.0
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        if url.startswith(('http://', 'https://')):
            url = url.split('//', 1)[1]
        return url.split('/')[0].split('?')[0]
    
    def _string_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using character overlap."""
        if not str1 or not str2:
            return 0.0
        
        # Simple Jaccard similarity on character bigrams
        bigrams1 = set(str1[i:i+2] for i in range(len(str1)-1))
        bigrams2 = set(str2[i:i+2] for i in range(len(str2)-1))
        
        if not bigrams1 or not bigrams2:
            return 0.0
        
        intersection = len(bigrams1 & bigrams2)
        union = len(bigrams1 | bigrams2)
        
        return intersection / union if union > 0 else 0.0


def score_threats(threat1: Dict[str, Any], threat2: Dict[str, Any]) -> float:
    """
    Convenience function to score two threats.
    
    Args:
        threat1: First threat record
        threat2: Second threat record
        
    Returns:
        Similarity score
    """
    scorer = ThreatScorer()
    return scorer.score_threats(threat1, threat2)


if __name__ == "__main__":
    # Example usage
    print("🎯 Threat Intelligence Scoring Module")
    print("=====================================")
    
    # Example threat data
    threat1 = {
        'id': 1,
        'indicator': 'https://fake-paypal-login.com/signin',
        'brand': 'PayPal',
        'ip_address': '192.168.1.100',
        'cert_serial_number': '12345ABCDEF',
        'cert_issuer': 'Let\'s Encrypt Authority X3',
        'registrar': 'GoDaddy',
        'hosting_asn': 'AS13335'
    }
    
    threat2 = {
        'id': 2,
        'indicator': 'https://paypal-secure-verify.com/login', 
        'brand': 'PayPal',
        'ip_address': '192.168.1.101',
        'cert_serial_number': '12345ABCDEF',
        'cert_issuer': 'Let\'s Encrypt Authority X3',
        'registrar': 'GoDaddy',
        'hosting_asn': 'AS13335'
    }
    
    # Score the threats
    score = score_threats(threat1, threat2)
    print(f"Similarity Score: {score:.2f}")
    
    # Show individual evidence contributions
    scorer = ThreatScorer()
    print("\nEvidence Breakdown:")
    for evidence_type, weight in scorer.weights.items():
        similarity = scorer._calculate_evidence_similarity(threat1, threat2, evidence_type)
        if similarity > 0:
            contribution = weight * similarity
            print(f"  {evidence_type}: {similarity:.1f} × {weight} = {contribution:.2f}")