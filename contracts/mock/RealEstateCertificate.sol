pragma solidity ^0.4.24;
import "../MultiSigDocument.sol";
import '../lib/strings.sol';

contract RealEstateCertificate is MultiSigDocument {
  using strings for *;
  struct Holder {
    string Name;
    string CitizenID;
  }

  event EntryUpdateRequest(address indexed doc, string fieldName);
  event EntrySet(address indexed doc, string fieldName);
  //Data
  string public CertName;
  string public AuthoritativeBody; // Verifier Name
  string public Address;
  string public Acreage; // in square meters

  mapping (address => Holder) holders; // each holder information
  bool public writable = false;

  constructor(
    address[] signers,
    address _verifier,
    string _certName,
    string _authoritativeBody,
    string _address,
    string _acreage
    )

  MultiSigDocument(signers, verifier, 1, 3650, 30)
  public
  {
      CertName = _certName;
      AuthoritativeBody = _authoritativeBody;
      Address = _address;
      Acreage = _acreage;
  }

  /* function setHolder(address holder, string _holderName, string _citizenId)
    public
    signerExists(holder) // holder must be a signer
    beforeModificationDeadline()
    onlyIssuer()
  {
    holders[holder] = Holder({ Name: _holderName, CitizenId: _citizenId});
  } */

  modifier isWritable() {
    assert(writable);
    _;
  }

  function setCertName(string newCertName)
    public
    onlyIssuer()
    beforeModificationDeadline()
    isWritable()
  {
    emit EntrySet(address(this), 'CertName');
    CertName = newCertName;
  }


  function requestToUpdate(string fieldName)
    public
    onlyVerifier()
  {
    writable = false;
    emit EntryUpdateRequest(address(this), fieldName);

  }

}
