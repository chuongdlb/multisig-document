pragma solidity ^0.4.24;

import "./MultiSigDocument.sol";
import "./lib/BytesToTypes.sol";
import "./lib/SizeOf.sol";
import "./lib/strings.sol";


contract MultiSigDocumentWithStorage is MultiSigDocument, ILockableStorage, BytesToTypes, SizeOf {
  using strings for *;
  string constant NULL_CHAR = '\u0000';
  //Data
  mapping (bytes32 => string) public entryStorage;
  // A long string contains all of the key allKeysInString
  /* string public allKeysInString; */

  string[] public entryKeys;
  bool public writable = false;

  constructor(
    address[] signers,
    address verifier,
    uint8 required,
    uint effectiveDurationInDay,
    uint offset,
    bytes buffer
    )
  MultiSigDocument(signers, verifier, required, effectiveDurationInDay, 30)
  /* validEntriesLength(entryKeys.length, entryValues.length) */
  public
  {
    /* allKeysInString = _enntryStr; */
    setData(offset, buffer);
  }

  modifier entryNotExisted(string memory entryKey) {
    assert(bytes(entryStorage[entryKey.toSlice().keccak()]).length == 0);
    _;
  }

  modifier entryExisted(string memory entryKey) {
    assert(bytes(entryStorage[entryKey.toSlice().keccak()]).length != 0);
    _;
  }
  modifier isWritable() {
    assert(writable);
    _;
  }

  function setData(uint offset, bytes memory buffer)
    internal
  {
    // Support only  value string with more than 32 chars
    while(offset > 0) {
      string memory valueStr = new string(getStringSize(offset, buffer));
      bytesToString(offset, buffer, bytes(valueStr));
      offset -= sizeOfString(valueStr);

      string memory keyStr = new string(getStringSize(offset, buffer));
      bytesToString(offset, buffer, bytes(keyStr));
      offset -= sizeOfString(keyStr);
      /* assert(bytes(keyStr).length <= 32);
      string memory strippedKey = valueStr.toSlice().split(NULL_CHAR.toSlice()).toString(); */

      string memory strippedVal = valueStr.toSlice().split(NULL_CHAR.toSlice()).toString();

      entryStorage[keyStr.toSlice().keccak()] = strippedVal;
      entryKeys.push(keyStr);
    }
  }

  function getAllKeys()
    public
    view
    returns (string memory out1)
  {
    for(uint32 i = 0 ; i < entryKeys.length; i++)
    {
      out1 = out1.toSlice().concat(entryKeys[i].toSlice()).toSlice().concat(";".toSlice());
    }
  }

  function getAllValues()
    public
    view
    returns (string memory out1)
  {
    for(uint32 i = 0 ; i < entryKeys.length; i++)
    {
      string memory s = entryStorage[entryKeys[i].toSlice().keccak()];
      out1 = out1.toSlice().concat(s.toSlice());
    }
  }

  function getProofHash()
    public
    view
    returns (bytes32)
  {
    return keccak256(abi.encodePacked(getAllValues()));
  }

  function addEntry(string memory key, string value)
    public
    isWritable()
    entryNotExisted(key)
    beforeModificationDeadline()
    onlyIssuer()
  {
    entryStorage[key.toSlice().keccak()] = value;
    /* string memory tmp = allKeysInString.toSlice().concat(",".toSlice());//.toSlice().concat(key.toSlice()); */
    entryKeys.push(key);
    emit EntrySet(address(this), key);
  }

  function updateEntry(string memory key, string value)
    public
    isWritable()
    beforeModificationDeadline()
    entryExisted(key)
    onlyIssuer()
  {
    entryStorage[key.toSlice().keccak()] = value;
    emit EntrySet(address(this), key);
  }

  function deleteEntry(string memory key)
    public
    beforeModificationDeadline()
    isWritable()
    onlyIssuer()
  {
    delete entryStorage[key.toSlice().keccak()]; //set entry to Default value of its type
    emit EntryDeleted(address(this), key);
  }

  function changeWritePermission(bool _writable, string memory key)
    public
    /* beforeModificationDeadline() */
    onlyVerifier()
  {
    writable = _writable;
    emit EntryUpdateRequest(address(this), key);
  }

  function getEntry(string memory key)
    public
    view
    returns (string)
  {
    return entryStorage[key.toSlice().keccak()];
  }
  function getKKHash(string memory s1)
    public
    view
    returns (bytes32)
  {
    return keccak256(abi.encodePacked(entryStorage[s1.toSlice().keccak()]));
  }

  function deleteDocument()
      public
      isExpired()
      allowDelete()
      signerExists(msg.sender)
  {
      // Refund all Ethers back to issuer
      selfdestruct(issuer);
  }
  // GDPR
  function deleteData()
      internal
  {

  }

}
