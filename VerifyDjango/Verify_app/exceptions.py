class IPFSHashNotReturnedException(Exception):
    """Exception raised when the IPFS hash is not returned from the IPFS network."""

    def __init__(self, message="IPFS hash was not returned from the network"):
        self.message = message
        super().__init__(self.message)