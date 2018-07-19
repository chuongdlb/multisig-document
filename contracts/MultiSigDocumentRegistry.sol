pragma solidity ^0.4.24;

import './MultiSigDocumentWithStorage.sol';
contract MultiSigDocumentRegistry {
  using strings for *;

  event DocumentIndexed(address indexed issuer, address indexed docAddr);
  event DocumentCreated(address indexed issuer, address indexed docAddr);
  event VerifierRegistration(address indexed issuer);

  struct Verifier {
      bool isVerifier;
      string Name;
      string Email;
  }
  //Store verifier info.
  mapping (address => Verifier) public verifierInfo;
  // Store created and indexed Document by Issuer's address
  mapping (address => mapping(uint => MultiSigDocumentWithStorage)) public docVault;
  // Keep track how many documents each Issuer have.
  mapping (address => uint) docCount;

  modifier onlyVerifier(bool isVerifier) {
      assert(isVerifier);
      _;
  }
  modifier onlyIssuer(bool isIssuer) {
      assert(isIssuer);
      _;
  }
  modifier isRegisteredVerifier(address a1) {
      assert(verifierInfo[a1].isVerifier);
      _;
  }

  constructor()
    public
  {

  }
  modifier stringNotEmpty(string memory s1) {
    assert(bytes(s1).length != 0);
    _;
  }
  function registerVerifier(string memory _name, string memory _email)
    public
    stringNotEmpty(_name)
    stringNotEmpty(_email)
  {
    verifierInfo[msg.sender] = Verifier({
        isVerifier: true,
        Name: _name,
        Email: _email
      });
    emit VerifierRegistration(msg.sender);
  }

  function createDocument(
    address[] signers,
    address verifier,
    uint8 required,
    uint validDays,
    uint offset,
    bytes buffer
  )
    public
    isRegisteredVerifier(verifier)
    returns (address)
  {
    docVault[msg.sender][docCount[msg.sender]] =
      new MultiSigDocumentWithStorage(signers, verifier, required, validDays, offset, buffer);

    docCount[msg.sender] = docCount[msg.sender] + 1;

    emit DocumentCreated(msg.sender, address(docVault[msg.sender][docCount[msg.sender]]));
    return docVault[msg.sender][docCount[msg.sender]];
  }

  function setDocument(MultiSigDocumentWithStorage doc)
    public
    onlyIssuer(doc.isIssuer(msg.sender))
  {
    /* docVault[msg.sender][docCount[msg.sender]] = Document({docAddr: docAddr}); */
    docVault[msg.sender][docCount[msg.sender]] = doc;

    docCount[msg.sender] = docCount[msg.sender] + 1;

    emit DocumentIndexed(msg.sender, address(doc));
  }

  function isVerified(address addr, uint docId)
    public
    view
    returns (bool)
  {
    return docVault[addr][docId].isVerified();
  }

  function getEntry(address issuer, uint docId, string memory key)
    public
    view
    returns (string)
  {
    return docVault[issuer][docId].getEntry(key);
  }





}
