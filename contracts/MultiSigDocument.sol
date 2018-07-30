pragma solidity ^0.4.24;

import './lib/ECRecovery.sol';

contract IMultipleSignatory {
    function isEnoughSignature() public view returns (bool);
    function changeNumberOfRquiredSignatures(uint newRequiredNumber) public;
    function isVerifier(address addr) public view returns (bool);
    function isIssuer(address addr) public view returns (bool);

    function signDocument(bytes memory sig) public;
    function verifyDocument() public;
    function revokeDocument() public;
    function deleteDocument() public;
    function submitDeleteConfirmation(bool deleted, bytes memory sig) public;
    function getProofHash() public view returns (bytes32);
    function isValidDataHash(bytes32 hash, bytes _sig) internal view returns(bool);
    function isVerified() public view returns (bool);

    event Verification(address indexed verifier, address indexed doc);
    event Revocation(address indexed verifier, address indexed doc);

    event LogInvalidSignatureSubmission(address submitter);
    event LogNumOfRequiredSignatureChanged(uint oldNum, uint indexed newNum);
    event DocumentSigned(address indexed document, address indexed verifier);
    event DeleteDocumentConfirmation(address indexed document, address indexed verifier);
}

contract MultiSigDocument is IMultipleSignatory {
  using ECRecovery for bytes32;
  uint public constant MAX_SIGNER_COUNT = 10;
  uint public createdTime; //Timestamp
  uint public validDays = 365; //days
  uint public expiration = 2**256-1; // Default to infinite time - Timestamp
  bool public autoActivation = false;
  bool public verified = false;
  uint public allowModificationDeadline = 0; //Timestamp
  uint public numOfRequiredSignature;

  address public verifier;
  address public issuer;
  // Keep track of signers
  // uint32 public signerCount = 0; // include issuer
  uint8 public finalizedSigConfirmations = 0;

  uint8 public deleteConfirmations = 0;

  mapping (address => SignerProperty) public signerProperties;

  address[] signers = new address[](MAX_SIGNER_COUNT);

  struct SignerProperty {
    bool IsSigner;
    bool IsSigned;
    bool DeleteConfirmed;
  }

  modifier validRequirement(uint _signerCount,
                            uint _numOfRequiredSignature,
                            uint _validDays,
                            uint _allowRevocationPeriodInDays)
  {
      require(_signerCount > 0 && _signerCount <= MAX_SIGNER_COUNT);
      require(_numOfRequiredSignature > 0  && _numOfRequiredSignature < MAX_SIGNER_COUNT);
      require(_validDays > 0 && _allowRevocationPeriodInDays < _validDays);
      _;
  }
  modifier signerDoesNotExist(address addr) {
      require(!signerProperties[addr].IsSigner);
      _;
  }
  // GDPR
  modifier allowDelete() {
      require(checkDeleteConfirmations());
      _;
  }

  modifier beforeModificationDeadline() {
      require(now < allowModificationDeadline);
      _;
  }

  modifier afterModificationDeadline() {
      require(now > allowModificationDeadline);
      _;
  }

  modifier signerExists(address addr) {
      require(signerProperties[addr].IsSigner);
      _;
  }

  modifier onlyVerifier() {
      require(verifier == msg.sender);
      _;
  }

  modifier isExpired() {
      require(now > expiration);
      _;
  }

  modifier onlyIssuer() {
      require(issuer == msg.sender);
      _;
  }
  modifier notVerified() {
      assert(!verified);
      _;
  }

  constructor(address[] _signer,
              address _verifier,
              uint _numOfRequiredSignature,
              uint _validDays,
              uint _allowRevocationPeriodInDays)
      public
      validRequirement(
        _signer.length,
        _numOfRequiredSignature,
        _validDays,
        _allowRevocationPeriodInDays)
  {
      for (uint i=0; i<_signer.length; i++) {
          assert(_signer[i] != address(0) && _signer[i] != msg.sender);
          signerProperties[_signer[i]].IsSigner = true;
          signers.push(_signer[i]);
      }
      issuer = msg.sender;
      signerProperties[issuer].IsSigner = true;

      signers.push(issuer);
      verifier = _verifier;

      createdTime = now;
      validDays = _validDays == 0 ? 0 : _validDays;
      expiration = _validDays == 0 ? expiration : (createdTime + (validDays * 1 days));
      numOfRequiredSignature = _numOfRequiredSignature + 1;
      allowModificationDeadline = createdTime + (_allowRevocationPeriodInDays * 1 days);
  }
  
  function isVerifier(address addr)
    public
    view
    returns (bool)
  {
    return (verifier == addr);
  }
  function isIssuer(address addr)
    public
    view
    returns (bool)
  {
    return (issuer == addr);
  }
  function submitDeleteConfirmation(bool confirmedDeleted, bytes memory sig)
      public
  {
      address recoveredAddr = keccak256(abi.encodePacked(address(this), confirmedDeleted))
        .toEthSignedMessageHash()
        .recover(sig);
      assert(signerProperties[recoveredAddr].IsSigner);
      assert(signerProperties[recoveredAddr].IsSigned);

      signerProperties[recoveredAddr].DeleteConfirmed = confirmedDeleted;
      emit DeleteDocumentConfirmation(address(this), verifier);
  }



  function changeNumberOfRquiredSignatures(uint newRequiredNumber)
      public
      onlyVerifier()
      beforeModificationDeadline()
      notVerified()
  {
      require(newRequiredNumber > 0  && newRequiredNumber < signers.length);
      emit LogNumOfRequiredSignatureChanged(numOfRequiredSignature, newRequiredNumber);
      numOfRequiredSignature = newRequiredNumber;
  }


  function signDocument(bytes  memory sig)
      public
      afterModificationDeadline()
  {
      if(!isValidSignature(sig)) {
        emit LogInvalidSignatureSubmission(msg.sender);
        revert('Submitting signature is invalid!');
      }
      address recoveredAddr = keccak256(
        abi.encodePacked(address(this), verifier, getProofHash()))
        .toEthSignedMessageHash()
        .recover(sig);
      signerProperties[recoveredAddr].IsSigned = true;
      finalizedSigConfirmations++;

      emit DocumentSigned(address(this), verifier);
  }

  /**
   * TODO: Overide this function
   */
  function getProofHash()
    public
    view
    returns (bytes32)
  {
    return keccak256(abi.encodePacked(""));
  }
  /**
   * @dev is the signature of `this + verifier + documentProofHash` from a signer?
   * @return bool
   */
  function isValidSignature(bytes _sig)
    internal
    view
    returns (bool)
  {
    return isValidDataHash(
      keccak256(abi.encodePacked(address(this), verifier, getProofHash())),
      _sig
    );
  }
  /**
   * @dev internal function to convert a hash to an eth signed message
   * and then recover the signature and check it against the bouncer role
   * @return bool
   */
  function isValidDataHash(bytes32 hash, bytes _sig)
    internal
    view
    returns (bool)
  {
    address recoveredAddr = hash
      .toEthSignedMessageHash()
      .recover(_sig);
    return signerProperties[recoveredAddr].IsSigner;
  }

  function isEnoughSignature()
      public
      view
      returns (bool)
  {

      if(!signerProperties[issuer].IsSigned) return false;
      if(finalizedSigConfirmations < numOfRequiredSignature) return false;
      return true;
  }

  function checkDeleteConfirmations()
      public
      view
      returns (bool)
  {
      uint8 _tmpCount = 0;
      for (uint8 i=0; i < signers.length; i++) {
          if (signerProperties[signers[i]].DeleteConfirmed == true)
            _tmpCount++;
      }
      if(_tmpCount < numOfRequiredSignature) {
          return false;

      }
      return true;
  }

  function verifyDocument()
      public
      notVerified()
      onlyVerifier()
      afterModificationDeadline()
  {
      /*
       * TODO: Please extend this function by adding validation of signature
       */
      assert(isEnoughSignature());
      verified = true;
      emit Verification(msg.sender, address(this));
  }

  function deleteDocument()
      public
      isExpired()
      allowDelete()
      signerExists(msg.sender)
  {
      /*
       * TODO: Please extend this function
       */
      selfdestruct(issuer);
  }
  function isVerified()
      public
      view
      returns (bool)
  {
      return verified;
  }

  function revokeDocument()
      public
      isExpired()
      onlyVerifier()
  {
      verified = false;
      emit Revocation(verifier, address(this));
  }
  function () public {
    //fallback
  }
}
